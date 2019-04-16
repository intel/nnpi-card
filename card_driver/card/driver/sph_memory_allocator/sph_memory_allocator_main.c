/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/stringify.h>
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>

#ifdef CARD_PLATFORM_BR
#include <linux/ion_exp.h>
#endif

#include "sph_log.h"
#include "sph_version.h"

/* The sph_mem module parameter defines physically contiguous
 * memory regions that will be managed by Memory Allocator
 *
 * sph_mem=size@start,size@start, ...
 */
static char *sph_mem;
static int test;
module_param(sph_mem, charp, 0400);
module_param(test, int, 0400);

#ifdef CARD_PLATFORM_BR

static void *ion_heap_handle;
static struct mem_chunk chunks[MAX_NUM_OF_CHUNKS];
static int num_of_chunks;

static int setup_sph_mem(char *param, struct mem_chunk *chunks, u32 num_of_chunks)
{
	phys_addr_t start = 0;
	size_t size = 0;
	char *curr, *p, *pp;
	int ret = 0;

	if (num_of_chunks > MAX_NUM_OF_CHUNKS)
		num_of_chunks = MAX_NUM_OF_CHUNKS;

	curr  = param;
	do {
		size = memparse(curr, &p);
		if (curr == p)
			return 0;

		if (*p == '@')
			start = memparse(p + 1, &pp);
		else
			return -1;

		if (p == pp)
			return -1;

		chunks[ret].base = start;
		chunks[ret].size = size;
		ret++;

		curr = strchr(curr, ',');
		if (!curr)
			break;
		curr++;
	} while (ret < num_of_chunks);

	return ret;
};

#define COMPARE_BYTE_SIZE 128

static void negate_buffer_data(char *data)
{
	int i;
	uint64_t *val = (uint64_t *)data;
	int val_iters = COMPARE_BYTE_SIZE / sizeof(uint64_t);

	for (i = 0; i < val_iters; i++) {
		*val = ~(*val);
		val++;
	}
}

static int compare_data(char *readBuf, char *expectedData)
{
	int i;
	uint64_t *valRead = (uint64_t *)readBuf;
	uint64_t *valExpected = (uint64_t *)expectedData;
	int val_iters = COMPARE_BYTE_SIZE / sizeof(uint64_t);

	for (i = 0; i < val_iters; i++) {
		if (*valRead != *valExpected)
			return 1;
		valRead++;
		valExpected++;
	}

	return 0;
}

//
// Check memory pages in COMPARE_BYTE_SIZE chunks
// return -1 incase of map fault
// return page number if memory corruption found
// return 0 on success
//
static int check_pages(struct page **pages, int num)
{
	int i;
	int iter_cnt = PAGE_SIZE / COMPARE_BYTE_SIZE;
	int page_cnt = 0;
	int total_size = PAGE_SIZE * num;
	int scanned_size = 0;
	char data[COMPARE_BYTE_SIZE];
	char readMem[COMPARE_BYTE_SIZE];
	void *start_addr = vm_map_ram(pages, num, -1, pgprot_noncached(pgprot_writecombine(PAGE_KERNEL)));
	void *addr = start_addr;
	void *page_addr = addr;

	if (!start_addr) {
		sph_log_err(START_UP_LOG, "Map failed\n");
		return -ENOMEM;
	}

	while (scanned_size < total_size) {
		page_addr = start_addr + page_cnt * PAGE_SIZE;

		for (i = 0; i < iter_cnt; i++) {
			addr = page_addr + i * COMPARE_BYTE_SIZE;
			//first read memory value
			memcpy(data, addr, COMPARE_BYTE_SIZE);

			//negate buffer data
			negate_buffer_data(data);

			//write data to mem
			memcpy(addr, data, COMPARE_BYTE_SIZE);

			//read memory
			memcpy(readMem, addr, COMPARE_BYTE_SIZE);

			//Compare read mem and data
			if (compare_data(readMem, data)) {
				vm_unmap_ram(start_addr, num);
				return page_cnt + 1; //incase page 0
			}

		}

		page_cnt++;
		scanned_size += PAGE_SIZE;
	}

	vm_unmap_ram(start_addr, num);
	return 0;
}


static int check_memory(phys_addr_t base, size_t size)
{
	int p = 0;
	int i = 0;
	int p_offset = 0;
	int ret = 0;
	size_t checked_size = 0;
	struct page *pages[32];
	unsigned long phys_base_addr = __phys_to_pfn(base);

	while (checked_size < size) {
		pages[p++] = pfn_to_page(phys_base_addr++);

		if (p == ARRAY_SIZE(pages)) {
			ret = check_pages(pages, p);
			if (ret != 0)
				return ret > 0 ? ret + p_offset : ret;
			p = 0;
			p_offset += ARRAY_SIZE(pages);
		}

		checked_size += PAGE_SIZE;
		i++;
	}
	if (p)
		ret = check_pages(pages, p);

	return ret > 0 ? ret + p_offset : ret;
}

static int split_chunk(int chunk_index, int page_index)
{
	struct mem_chunk chunk1, chunk2;
	int i;

	if (num_of_chunks + 1 > MAX_NUM_OF_CHUNKS) {
		sph_log_err(START_UP_LOG, "Failed to split chunk max num of chunks reached\n");
		return -1;
	}
	num_of_chunks++;

	chunk1.size = (page_index - 1) * PAGE_SIZE;
	chunk2.size = chunks[chunk_index].size - (chunk1.size + PAGE_SIZE);

	chunk1.base = chunks[chunk_index].base;
	chunk2.base = chunk1.base + chunk1.size + PAGE_SIZE;

	sph_log_debug(START_UP_LOG, "chunk split orig chunk size %lu addr 0x%llx , chunk1 size %lu addr 0x%llx , chunk2 size %lu addr 0x%llx\n",
		 chunks[chunk_index].size,
		 chunks[chunk_index].base,
		 chunk1.size, chunk1.base,
		 chunk2.size, chunk2.base);

	i = num_of_chunks;
	while (i >= chunk_index) {
		if (i == chunk_index)
			memcpy(&chunks[i], &chunk1, sizeof(struct mem_chunk));
		else if (i == chunk_index + 1)
			memcpy(&chunks[i], &chunk2, sizeof(struct mem_chunk));
		else
			memcpy(&chunks[i], &chunks[i - 1], sizeof(struct mem_chunk));

		i--;
	}

	return 0;
}


static int test_memory(void)
{
	int i = 0;
	int ret;
	int fault_page;

	while (i < MAX_NUM_OF_CHUNKS) {
		ret = check_memory(chunks[i].base, chunks[i].size);
		if (ret < 0) { //Maybe we need to split chunk here
			sph_log_err(START_UP_LOG, "Failed to access memory\n");
			return -1;
		}

		if (ret > 0) { //page check error , remove page from chunk and split chunk
			fault_page = ret - 1;
			sph_log_err(START_UP_LOG, "page %d is corrupted split chunk and skip page\n", fault_page);
			//split  chunk and modify chunk list
			if (split_chunk(i, fault_page) < 0) {
				sph_log_err(START_UP_LOG, "Failed to split chunk\n");
				return -1;
			}
		}
		i++;
	}

	return 0;
}

#endif

int sph_memory_allocator_init_module(void)
{
	int ret = 0;

	sph_log_debug(START_UP_LOG, "module (version %s) started\n", SPH_VERSION);
#ifdef CARD_PLATFORM_BR
	num_of_chunks = setup_sph_mem(sph_mem, chunks, MAX_NUM_OF_CHUNKS);
	if (num_of_chunks <= 0)
		ret = -EINVAL;

	if (test == 1 && test_memory() < 0)
		sph_log_err(START_UP_LOG, "Memory Test Failed\n");

	ion_heap_handle = ion_chunk_heap_setup(chunks, num_of_chunks);
#endif
	return ret;
}

void sph_memory_allocator_cleanup(void)
{
	sph_log_debug(GO_DOWN_LOG, "Cleaning Up the Module\n");
#ifdef CARD_PLATFORM_BR
	ion_chunk_heap_remove(ion_heap_handle);
#endif
}

module_init(sph_memory_allocator_init_module);
module_exit(sph_memory_allocator_cleanup);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SpringHill Card memory allocator");
MODULE_AUTHOR("Intel Corporation");
MODULE_VERSION(SPH_VERSION);
#ifdef DEBUG
MODULE_INFO(git_hash, SPH_GIT_HASH);
#endif
