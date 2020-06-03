/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _ICE_SAFE_FUNC_H_
#define _ICE_SAFE_FUNC_H_

#include <linux/string.h>
#include <linux/errno.h>

#ifdef RING3_VALIDATION
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#endif

#define errno_t int
#define MAX_STR_LENGTH 1024
#define MAX_FMT_ID 10

/*sprintf */
#define CHAR_ID 'c'
#define WCHAR_ID 'C'
#define SHORT_ID 'h'
#define INT_ID 'd'
#define LONG_ID 'l'
#define STRING_ID 's'
#define WSTRING_ID 'S'
#define DOUBLE_ID 'g'
#define LDOUBLE_ID 'G'
#define VOID_ID 'p'
#define PCHAR_ID '1'
#define PSHORT_ID '2'
#define PINT_ID '3'
#define PLONG_ID '4'
#define UNSIGN_ID 'u'

#define CHK_FORMAT(X, Y) (((X) == (Y))?1:0)

int ice_strlen_s(const char *dest, int dest_max);

int ice_memset_s(void *src, size_t src_limit, int c, size_t n);

/* if src is shorter, dst will be filled with zeros up to dst_size */
bool ice_safe_memcpy(void *dst, size_t dst_size,
		const void *src, size_t max_size);

/* 0 on success, -1 on failure */
int ice_memcpy_s(void *dst, size_t dst_size,
	const void *src, size_t max_size);

bool ice_safe_strncpy(char *dst, size_t dst_size,
		const char *src, size_t max_num_chars);

int ice_strncpy_s(char *dst, size_t dst_size,
		const char *src, size_t max_num_chars);

bool ice_safe_strcat(char *dest, size_t dest_size, const char *src);

int ice_strcat_s(char *dest, size_t dest_size, const char *src);

uint32_t parse_fmt_str(const char *format, char format_id_list[],
		unsigned int maxFormats);
uint32_t check_uint_format(const char format);

uint32_t verify_integer_format(const char format);

int ice_snprintf_s_s(char *dest, size_t dmax, const char *format,
		const char *s);

int ice_snprintf_s_si(char *dest, size_t dmax, const char *format,
		const char *s, int a);

int ice_snprintf_s_su(char *dest, size_t dmax, const char *format,
		const char *s, uint64_t a);

int ice_snprintf_s_ssss(char *dest, size_t dmax, const char *format,
	       const char *s1, const char *s2, const char *s3, const char *s4);

int ice_snprintf_s(char *dest, size_t dest_size, const char *format);

int ice_snprintf_s_i(char *dest, size_t dest_size, const char *format,
		int val1);

int ice_snprintf_s_ii(char *dest, size_t dsize, const char *format, int val1,
		int val2);

int ice_snprintf_s_u(char *dest, size_t dest_size, const char *format,
		uint64_t val1);

int ice_snprintf_s_uu(char *dest, size_t dest_size, const char *format,
		uint64_t val1, uint64_t val2);

int ice_snprintf_s_iiiss(char *dest, size_t dmax, const char *format,
		int a1, int a2, int a3, const char *s1, const char *s2);

int ice_snprintf_s_uuuuu(char *dest, size_t dmax, const char *format,
		uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
		uint64_t a5);

int ice_snprintf_s_uuuuuuuu(char *dest, size_t dmax, const char *format,
		uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
		uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8);

int ice_snprintf_s_uuuss(char *dest, size_t dmax, const char *format,
		uint64_t a1, uint64_t a2, uint64_t a3,
		const char *s1, const char *s2);

int ice_snprintf_s_iisss(char *dest, size_t dmax, const char *format,
		int a1, int a2, const char *s1, const char *s2, const char *s3);

int ice_snprintf_s_uusss(char *dest, size_t dmax, const char *format,
		uint64_t a1, uint64_t a2, const char *s1, const char *s2,
		const char *s3);

int ice_sscanf_s_u8(const char *src, const char *format,
		uint8_t *dest);

int ice_sscanf_s_u32(const char *src, const char *format,
		uint32_t *dest);
#endif /* _ICE_SAFE_FUNC_H_ */

