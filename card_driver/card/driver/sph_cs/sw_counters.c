#include "sw_counters.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>
#include "sph_log.h"


#define SPH_SW_COUNTERS_GLOBAL_DIR_NAME		"sw_counters"

#define SPH_COUNTER_SIZE			(sizeof(u64))

#define SW_COUNTERS_TO_INTERNAL(a) ((struct sph_internal_sw_counters *)(((char *)a) - offsetof(struct sph_internal_sw_counters, sw_counters)))

#define MAX_STALE_ATTR_NAME_LEN    32

#define SW_COUNTERS_ASSERT(x)						\
	do {							\
		if (likely(x))					\
			break;					\
		pr_err("SPH ASSERTION FAILED %s: %s: %u: %s\n", \
			__FILE__, __func__, __LINE__, #x);      \
		BUG();                                          \
	} while (0)

/* file attributre for group file */
struct sph_sw_counters_group_file_attr {
	struct attribute attr;
	ssize_t (*show)(struct kobject *kobj, struct attribute *attr, char *buf);
	ssize_t (*store)(struct kobject *a, struct attribute *b, const char *c, size_t count);
	u32	*enable;
};

/* file attribute for binary file */
struct sph_sw_counters_bin_file_attr {
	struct bin_attribute		attr;
	struct page			*bin_page;
	u32				page_count;
	char				*info_buf;
	ssize_t				info_size;
	u64                             dirty_at_remove;
};

struct bin_stale_node {
	struct kobject			    *kobj;
	struct sph_sw_counters_bin_file_attr bin_file;
	struct list_head		     node;
	struct list_head                     kobject_list;
};

struct kobj_node {
	struct list_head				node;
	struct kobject					*kobj;
};

struct gen_sync_attr {
	struct attribute attr;
	ssize_t (*show)(struct kobject *kobj, struct attribute *attr, char *buf);
	ssize_t (*store)(struct kobject *a, struct attribute *b, const char *c, size_t count);
	struct list_head  stale_list;
	spinlock_t        lock;
	struct list_head  sync_clients;
	u32		  stale_seq;
	u64               last_remove_dirty_val;
};

struct sync_client {
	struct gen_sync_attr *gen_sync;
	u64                   last_refresh_dirty;
	struct list_head      node;
};


struct sph_internal_sw_counters {
	struct list_head				node;
	struct kobject					*kobj;
	bool						kobj_owner;
	struct kobject					*groups_kobj;
	struct sph_sw_counters_bin_file_attr		bin_file;
	struct sph_sw_counters_group_file_attr		*groups_files;
	const struct sph_sw_counters_set		*counters_set;
	struct list_head				children_List;
	struct list_head				kobject_list;
	struct mutex					list_lock;
	u64						*dirty;
	struct sph_internal_sw_counters			*info_node;
	struct sph_sw_counters				sw_counters;
	struct sph_internal_sw_counters			*parent;
	struct gen_sync_attr			        *gen_sync_attr;
};

static DEFINE_MUTEX(values_tree_sync_mutex);

/* create counters description buffer object */
int create_sw_counters_description_data(const  struct sph_sw_counters_set *counters_set,
					bool isRoot,
					char **buffer,
					ssize_t *buffer_size)
{
	u32 alloc_size = 1; // 1 for NULL terminating char
	u32 i;
	char *pos;
	ssize_t offset = 0;


	alloc_size += snprintf(NULL, 0, ",dirty_values,%d,in case a new values created or destroyed value is incremented\n",
			       (u32)(0));
	offset++;

	if (isRoot) {
		alloc_size += snprintf(NULL, 0, ",dirty_info,%d,in case a new info file created or destroyed value is incremented\n",
				       (u32)(SPH_COUNTER_SIZE));
		offset++;
	}

	/* first we calculate required size for description buffer */
	for (i = 0; i < counters_set->counters_count; i++) {
		/* if groups_id value is equal or higher than groups_count we type NA */
		if (counters_set->counters_info[i].group_id < counters_set->groups_count)
			alloc_size += snprintf(NULL, 0, "%s,%s,%d,%s\n",
					       counters_set->groups_info[counters_set->counters_info[i].group_id].name,
					       counters_set->counters_info[i].name,
					       (u32)((i+offset) * SPH_COUNTER_SIZE),
					       counters_set->counters_info[i].description);
		else
			alloc_size += snprintf(NULL, 0, ",%s,%d,%s\n",
					       counters_set->counters_info[i].name,
					       (u32)((i+offset) * SPH_COUNTER_SIZE),
					       counters_set->counters_info[i].description);

	}

	/* try to allocate buffer in given size */
	*buffer = kmalloc_array(alloc_size, sizeof(char), GFP_KERNEL);
	if (!*buffer) {
		sph_log_err(GENERAL_LOG, "unable to allocated counters description array size: %d\n", alloc_size);
		return -ENOMEM;
	}

	*buffer_size = alloc_size;
	pos = *buffer;

	alloc_size = sprintf(pos, ",dirty_values,%d,in case a new values created or destroyed value is incremented\n",
			       (u32)(0));
	pos += alloc_size;

	if (isRoot) {
		alloc_size = sprintf(pos, ",dirty_info,%d,in case a new info file created or destroyed value is incremented\n",
				       (u32)(SPH_COUNTER_SIZE));
		pos += alloc_size;
	}


	/* print description data into allocated buffer */
	for (i = 0; i < counters_set->counters_count; i++) {
		/* if groups_id value is equal or higher than groups_count we type NA */
		if (counters_set->counters_info[i].group_id < counters_set->groups_count)
			alloc_size = sprintf(pos, "%s,%s,%d,%s\n",
					     counters_set->groups_info[counters_set->counters_info[i].group_id].name,
					     counters_set->counters_info[i].name,
					     (u32)((i+offset) * SPH_COUNTER_SIZE),
					     counters_set->counters_info[i].description);
		else
			alloc_size = sprintf(pos, ",%s,%d,%s\n",
					     counters_set->counters_info[i].name,
					     (u32)((i+offset) * SPH_COUNTER_SIZE),
					     counters_set->counters_info[i].description);
		pos += alloc_size;
	}

	return 0;
}

/* mmap to binary file contaning all counters information */
static int mmap_sph_counter_bin_values(struct file *f,
				struct kobject *kobj,
				struct bin_attribute *attr,
				struct vm_area_struct *vma)
{
	int ret;

	struct sph_sw_counters_bin_file_attr *counters_att = (struct sph_sw_counters_bin_file_attr *)attr;
	unsigned long size = vma->vm_end - vma->vm_start;

	/* we limit mmap for a single page only */
	if (size > PAGE_SIZE)
		return -EINVAL;

	/*
	 * detach this allocation from the attribute file,
	 * so that the mapping will survive file destruction
	 */
	if (vma->vm_file) {
		fput(vma->vm_file);
		vma->vm_file = NULL;
	}

	/* map the page to user */
	ret = vm_insert_page(vma, vma->vm_start, counters_att->bin_page);

	return ret;
}

static ssize_t read_sph_counter_bin_values(struct file *f,
					   struct kobject *kobj,
					   struct bin_attribute *attr,
					   char *buf,
					   loff_t offset,
					   size_t count)
{
	ssize_t ret;

	struct sph_sw_counters_bin_file_attr *counters_att = (struct sph_sw_counters_bin_file_attr *)attr;

	if (!counters_att->bin_page || !counters_att->page_count)
		ret = -1;
	else
		ret = memory_read_from_buffer(buf,
					      count,
					      &offset,
					      page_address(counters_att->bin_page),
					      counters_att->page_count * PAGE_SIZE);
	return ret;
}

/* show counter descriptor */
ssize_t read_counters_descriptor(struct file *file,
				 struct kobject *kobj,
				 struct bin_attribute *attr,
				 char *buf,
				 loff_t pos,
				 size_t count)
{
	struct sph_sw_counters_bin_file_attr *counters_att = (struct sph_sw_counters_bin_file_attr *)attr;

	/* check for minimum value - buffer length or requested count */
	count = min((u32)(counters_att->info_size - (u32)pos), (u32)count);

	/* copy output to buffer */
	memcpy(buf, counters_att->info_buf + pos, count);

	return count;
}

/* set counter groups to enable for sph_internal_sw_counters */
static ssize_t store_sph_sw_counters_group_enable(struct kobject *kobj,
						  struct attribute *attr,
						  const char *buf,
						  size_t count)
{
	struct sph_sw_counters_group_file_attr *counters_att = (struct sph_sw_counters_group_file_attr *)attr;
	u32 val;
	ssize_t ret;

	ret = kstrtoint(buf, 10, &val);
	if (ret != 0)
		goto sph_counters_bad_input;

	if (val)
		(*counters_att->enable)++;
	else if (*counters_att->enable)
		(*counters_att->enable)--;

	return count;

sph_counters_bad_input:
	return ret;
}

/* set counter groups to enable for sph_internal_sw_counters */
static ssize_t  show_sph_sw_counters_group_enable(struct kobject *kobj,
						  struct attribute *attr,
						  char *buf)
{
	struct sph_sw_counters_group_file_attr *counters_att = (struct sph_sw_counters_group_file_attr *)attr;

	return scnprintf(buf, PAGE_SIZE, "%d\n", *(counters_att->enable));
}

int create_sph_bin_file(struct kobject *kobj, struct sph_sw_counters_bin_file_attr *attr, const u32 allocation_size)
{
	int ret;
	u32 page_count;

	/* calculate required pages for given allocation */
	page_count = (allocation_size + PAGE_SIZE - 1) / PAGE_SIZE;

	if (page_count) {
		/* allocate page for counter values information */
		attr->bin_page = alloc_pages(GFP_KERNEL, get_order(page_count));
		if (!attr->bin_page) {
			sph_log_err(GENERAL_LOG, "unable to allocate page for file : %s\n", attr->attr.attr.name);
			return -ENOMEM;
		}

		/* set page size */
		attr->page_count = page_count;

		/* initialize allocated pages to zero */
		memset(page_address(attr->bin_page),
		       0,
		       page_count * PAGE_SIZE);
	}


	sysfs_bin_attr_init(&attr->attr);

	ret = sysfs_create_bin_file(kobj, &attr->attr);

	if (ret) {
		sph_log_err(GENERAL_LOG, "unable to create binary file: %s\n", attr->attr.attr.name);
		if (page_count)
			goto cleanup_page;
		return ret;
	}


	return ret;

cleanup_page:
	if (attr->bin_page)
		__free_pages(attr->bin_page, get_order(page_count));

	attr->bin_page = NULL;
	attr->page_count = 0x0;

	return ret;
}

int create_sph_file(struct kobject *kobj, struct attribute *attr)
{
	int ret;

	sysfs_attr_init(attr);

	ret = sysfs_create_file(kobj, attr);

	return ret;
}


/* free binary file */
void release_bin_file(struct kobject *kobj, struct sph_sw_counters_bin_file_attr *attr)
{
	sysfs_remove_bin_file(kobj, &attr->attr);

	/* if we have allocated a page - we need to release it */
	if (attr->page_count)
		__free_pages(attr->bin_page, get_order(attr->page_count));

	if (attr->info_size)
		kfree(attr->info_buf);
}

static void move_to_stale_list(struct gen_sync_attr                 *gen_sync,
			       struct kobject                       *kobj,
			       struct sph_sw_counters_bin_file_attr *attr,
			       struct list_head                     *kobject_list,
			       u64                                   dirty_val)
{
	struct bin_stale_node *stale_node;
	int ret;
	int stale_id;
	struct kobj_node *kobj_node;

	stale_node = kzalloc(sizeof(*stale_node) + MAX_STALE_ATTR_NAME_LEN,
			     GFP_KERNEL);
	if (!stale_node)
		goto fail_alloc;

	INIT_LIST_HEAD(&stale_node->kobject_list);
	SW_COUNTERS_ASSERT(kobject_list != NULL);
	list_for_each_entry(kobj_node, kobject_list, node) {
		struct kobj_node *new_kobj = kzalloc(sizeof(*new_kobj), GFP_KERNEL);

		if (new_kobj == NULL) {
			sph_log_err(GENERAL_LOG, "unable to allocate memory for new_kobj\n");
			goto fail_create_list;
		}
		new_kobj->kobj = kobject_get(kobj_node->kobj);
		list_add_tail(&new_kobj->node, &stale_node->kobject_list);
	}

	stale_node->kobj = kobject_get(kobj);
	memcpy(&stale_node->bin_file, attr, sizeof(struct sph_sw_counters_bin_file_attr));

	spin_lock(&gen_sync->lock);
	if (++gen_sync->stale_seq == 0)
		gen_sync->stale_seq = 1;
	stale_id = gen_sync->stale_seq;
	spin_unlock(&gen_sync->lock);

	sprintf((char *)(stale_node+1),
		"stale_%s_%06d",
		attr->attr.attr.name, stale_id);

	stale_node->bin_file.attr.attr.name = (const char *)(stale_node+1);
	stale_node->bin_file.dirty_at_remove = dirty_val;

	ret = sysfs_create_bin_file(kobj, &stale_node->bin_file.attr);
	if (ret)
		goto fail_create;

	spin_lock(&gen_sync->lock);
	list_add_tail(&stale_node->node, &gen_sync->stale_list);
	spin_unlock(&gen_sync->lock);

	sysfs_remove_bin_file(kobj, &attr->attr);

	return;

fail_create:
	kobject_put(stale_node->kobj);
fail_create_list:
	while (!list_empty(&stale_node->kobject_list)) {
		kobj_node = list_first_entry(&stale_node->kobject_list, struct kobj_node, node);
		list_del(&kobj_node->node);
		kobject_put(kobj_node->kobj);
		kfree(kobj_node);
	}
	kfree(stale_node);
fail_alloc:
	sph_log_err(GENERAL_LOG, "Failed to create stale attr, removing object!!\n");
	release_bin_file(kobj, attr);
}

static void remove_stale_bin_files(struct gen_sync_attr *gen_sync,
				   u64                   dirty_val,
				   bool                  force)
{
	struct bin_stale_node *stale_node;
	struct bin_stale_node *n;

	spin_lock(&gen_sync->lock);
	list_for_each_entry_safe(stale_node, n, &gen_sync->stale_list, node) {
		if (force ||
		    (stale_node->bin_file.dirty_at_remove <= dirty_val)) {
			struct kobj_node *kobj_node;

			list_del(&stale_node->node);
			spin_unlock(&gen_sync->lock);
			release_bin_file(stale_node->kobj, &stale_node->bin_file);
			while (!list_empty(&stale_node->kobject_list)) {
				kobj_node = list_first_entry(&stale_node->kobject_list, struct kobj_node, node);
				list_del(&kobj_node->node);
				kobject_put(kobj_node->kobj);
				kfree(kobj_node);
			}
			kobject_put(stale_node->kobj);
			kfree(stale_node);
			spin_lock(&gen_sync->lock);
		}
	}
	spin_unlock(&gen_sync->lock);
}

/* free text file */
void release_file(struct kobject *kobj, struct sph_sw_counters_group_file_attr *attr)
{
	sysfs_remove_file(kobj, (struct attribute *)attr);
}


static int create_group_files(struct kobject *kobj,
			      struct sph_internal_sw_counters *sw_counters,
			      u32 *buffer)
{
	int ret;
	u32 i, j;
	const u32 groups_count = sw_counters->counters_set->groups_count;

	sw_counters->groups_kobj = kobject_create_and_add("groups", kobj);
	sw_counters->groups_files = kmalloc_array(groups_count, sizeof(struct sph_sw_counters_group_file_attr), GFP_KERNEL);
	if (!sw_counters->groups_files) {
		sph_log_err(GENERAL_LOG, "unable to allocate sw_counter groups files array for groups\n");
		ret = -ENOMEM;
		goto failed_to_allocate_array;
	}

	for (i = 0; i < groups_count; i++) {
		sw_counters->groups_files[i].attr.name	= sw_counters->counters_set->groups_info[i].name;
		sw_counters->groups_files[i].attr.mode	= 0666;
		sw_counters->groups_files[i].show = show_sph_sw_counters_group_enable;
		sw_counters->groups_files[i].store = store_sph_sw_counters_group_enable;
		sw_counters->groups_files[i].enable = &(buffer[i]);

		ret = create_sph_file(sw_counters->groups_kobj, (struct attribute *)&sw_counters->groups_files[i]);
		if (unlikely(ret < 0)) {
			sph_log_err(GENERAL_LOG, "unable to create group %s file for groups\n", sw_counters->counters_set->groups_info[i].name);
			goto failed_to_create_file;
		}

	}

	return 0;

failed_to_create_file:
	/* Remove already created files */
	for (j = 0; j < i; j++)
		release_file(sw_counters->groups_kobj, &sw_counters->groups_files[i]);

	kobject_put(sw_counters->groups_kobj);

	kfree(sw_counters->groups_files);
failed_to_allocate_array:
	return ret;
}

static void remove_group_files(struct sph_internal_sw_counters *sw_counters)
{
	u32 i;

	if (sw_counters->groups_kobj == NULL)
		return;

	for (i = 0; i < sw_counters->counters_set->groups_count; i++)
		release_file(sw_counters->groups_kobj, &sw_counters->groups_files[i]);

	kobject_put(sw_counters->groups_kobj);

	kfree(sw_counters->groups_files);
}

static void client_refresh_dirty_updated(struct gen_sync_attr *gen_sync)
{
	mutex_lock(&values_tree_sync_mutex);

	if (list_empty(&gen_sync->sync_clients)) {
		remove_stale_bin_files(gen_sync, 0, true);
		gen_sync->last_remove_dirty_val = 0;
	} else {
		struct sync_client *client;
		u64 min_dirty_val = U64_MAX;

		spin_lock(&gen_sync->lock);
		list_for_each_entry(client, &gen_sync->sync_clients, node) {
			if (client->last_refresh_dirty < min_dirty_val)
				min_dirty_val = client->last_refresh_dirty;
		}
		spin_unlock(&gen_sync->lock);

		if (min_dirty_val > gen_sync->last_remove_dirty_val) {
			remove_stale_bin_files(gen_sync, min_dirty_val, false);
			gen_sync->last_remove_dirty_val = min_dirty_val;
		}
	}

	mutex_unlock(&values_tree_sync_mutex);
}

static int gen_sync_release(struct inode *inode, struct file *f)
{
	struct sync_client *client = (struct sync_client *)f->private_data;

	spin_lock(&client->gen_sync->lock);
	list_del(&client->node);
	spin_unlock(&client->gen_sync->lock);

	client_refresh_dirty_updated(client->gen_sync);

	kfree(client);
	return 0;
}

static long gen_sync_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct sync_client *client = (struct sync_client *)f->private_data;
	u64 dirty_val;

	/*
	 * only single ioctl command, 0, is supported to set the last
	 * refresh dirty count
	 */
	if (cmd != 0)
		return -EINVAL;

	if (copy_from_user(&dirty_val, (void __user *)arg, sizeof(u64)) != 0)
		return -EINVAL;

	client->last_refresh_dirty = dirty_val;

	client_refresh_dirty_updated(client->gen_sync);

	return 0;
}

static const struct file_operations gen_sync_fops = {
	.owner = THIS_MODULE,
	.release = gen_sync_release,
	.unlocked_ioctl = gen_sync_ioctl,
	.compat_ioctl = gen_sync_ioctl,
};

/* gen sync attr show function - generates sync fd */
static ssize_t  show_gen_sync(struct kobject *kobj,
			      struct attribute *attr,
			      char *buf)
{
	struct gen_sync_attr *gen_sync = (struct gen_sync_attr *)attr;
	struct sync_client *client;
	int fd = -1;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		goto done;

	client->gen_sync = gen_sync;

	fd = anon_inode_getfd("sph_counters_gen_sync",
			      &gen_sync_fops,
			      client,
			      O_RDWR);
	if (fd < 0) {
		kfree(client);
		goto done;
	}

	spin_lock(&gen_sync->lock);
	list_add_tail(&client->node, &gen_sync->sync_clients);
	spin_unlock(&gen_sync->lock);

done:
	return scnprintf(buf, PAGE_SIZE, "%d\n", fd);
}

static struct gen_sync_attr *create_gen_sync_attr(struct kobject *kobj)
{
	struct gen_sync_attr *gen_sync;
	int ret;

	gen_sync = kzalloc(sizeof(*gen_sync), GFP_KERNEL);
	if (!gen_sync)
		return NULL;

	gen_sync->attr.name = "gen_sync_fd";
	gen_sync->attr.mode = 0444;
	gen_sync->show = show_gen_sync;
	INIT_LIST_HEAD(&gen_sync->stale_list);
	INIT_LIST_HEAD(&gen_sync->sync_clients);
	spin_lock_init(&gen_sync->lock);

	ret = create_sph_file(kobj, &gen_sync->attr);
	if (ret) {
		sph_log_err(GENERAL_LOG, "Failed to create stale_enable attribute\n");
		kfree(gen_sync);
		return NULL;
	}

	return gen_sync;
}

static inline bool gen_sync_has_clients(struct gen_sync_attr *gen_sync)
{
	if (gen_sync)
		return !list_empty(&gen_sync->sync_clients);
	else
		return false;
}

int sph_create_sw_counters_info_node(struct kobject *kobj,
				     const struct sph_sw_counters_set	*counters_set,
				     void *hParentInfo,
				     void **hNewInfo)
{
	int ret;
	struct sph_internal_sw_counters *sw_counters_info;
	struct sph_internal_sw_counters *parent_sw_counters_info = (struct sph_internal_sw_counters *)hParentInfo;

	sw_counters_info = kzalloc(sizeof(*sw_counters_info), GFP_KERNEL);
	if (!sw_counters_info) {
		sph_log_err(GENERAL_LOG, "unable to generate sph_sw_counters_object\n");
		return -ENOMEM;
	}


	/* set parent node */
	sw_counters_info->parent =  parent_sw_counters_info;

	/* in case we are using parent node, kobject must be a child of parent, and if no kobj input given driver will use this module */
	if (sw_counters_info->parent)
		kobj = sw_counters_info->parent->kobj;
	else if (kobj == NULL) {
		struct module *module = THIS_MODULE;

		if (!module) {
			sph_log_err(GENERAL_LOG, "Could not retrieve module owner!\n");
			ret = -EINVAL;
			goto cleanup_sw_counters_info;
		}

		kobj =  &module->mkobj.kobj;
	}

	/* save counters set input */
	sw_counters_info->counters_set = counters_set;

	/* create counters set directory for given kobj */
	sw_counters_info->kobj = kobject_create_and_add(counters_set->name, kobj);
	if (!sw_counters_info->kobj) {
		sph_log_err(GENERAL_LOG, "unable to create kobject directory for %s\n", counters_set->name);
		ret = -ENOMEM;
		goto cleanup_sw_counters_info;
	}

	/* now we can set kobj to use created directory */
	kobj = sw_counters_info->kobj;

	/* set directory owner as current sw counters info object */
	sw_counters_info->kobj_owner = true;

	/* create/set gen sync attribute file (exist on root node only) */
	if (sw_counters_info->parent)
		sw_counters_info->gen_sync_attr =
			sw_counters_info->parent->gen_sync_attr;
	else {
		sw_counters_info->gen_sync_attr = create_gen_sync_attr(kobj);
		if (sw_counters_info->gen_sync_attr == NULL) {
			sph_log_err(GENERAL_LOG, "failed to create sync attr\n");
			ret = -ENOMEM;
			goto cleanup_sw_counters_info;
		}
	}

	/* define counters info - this is a readonly binary file */
	/* in case of counters set input as perID info file name will end with .perID */
	if (sw_counters_info->counters_set->perID)
		sw_counters_info->bin_file.attr.attr.name	= "info.perID";
	else
		sw_counters_info->bin_file.attr.attr.name	= "info";

	sw_counters_info->bin_file.attr.attr.mode	= 0444;
	sw_counters_info->bin_file.attr.read	= read_counters_descriptor;
	sw_counters_info->bin_file.bin_page	= NULL;
	sw_counters_info->bin_file.page_count	= 0x0;

	/* create description buffer for counters set input - will be freed on file close */
	ret = create_sw_counters_description_data(counters_set,
						  (sw_counters_info->parent == NULL),
						  &sw_counters_info->bin_file.info_buf,
						  &sw_counters_info->bin_file.info_size);
	if (ret) {
		sph_log_err(GENERAL_LOG, "unable to create info buffer for %s\n", counters_set->name);
		goto cleanup_sw_counters_kobj;
	}
	/* create binary file - will present counters description */
	ret = create_sph_bin_file(kobj, &sw_counters_info->bin_file, 0x0);
	if (ret) {
		sph_log_err(GENERAL_LOG, "unable to create sw_counters info file for %s\n", counters_set->name);
		goto cleanup_sw_counters_description_data;
	}

	/* allocate default groups values - in case this is not perID counters this will be used as values groups enable*/
	sw_counters_info->sw_counters.groups =
		kmalloc_array(counters_set->groups_count,
			      sizeof(u32),
			      GFP_KERNEL | __GFP_ZERO);
	if (!sw_counters_info->sw_counters.groups) {
		sph_log_err(GENERAL_LOG, "unable to allocate sw_counter groups array for %s\n", counters_set->name);
		ret = -ENOMEM;
		goto cleanup_sw_counters_bin_file;
	}


	/* create set of groups files under groups directory */
	ret = create_group_files(kobj, sw_counters_info, sw_counters_info->sw_counters.groups);
	if (ret)
		goto cleanup_sw_counters_groups_buffer;

	sw_counters_info->sw_counters.global_groups = sw_counters_info->sw_counters.groups;

	/* initialize global list of buffer of sw_counters_info children */
	INIT_LIST_HEAD(&sw_counters_info->children_List);
	mutex_init(&sw_counters_info->list_lock);

	/* in case this is not a root node - we need to register this node for it's parent */
	if (sw_counters_info->parent) {
		mutex_lock(&sw_counters_info->parent->list_lock);
		list_add_tail(&sw_counters_info->node,
			      &sw_counters_info->parent->children_List);
		mutex_unlock(&sw_counters_info->parent->list_lock);
	}

	*hNewInfo = (void *)sw_counters_info;

	/* update root node dirty info, in case of late creation of info object */
	while (sw_counters_info) {
		if (sw_counters_info->parent == NULL &&
		    sw_counters_info->dirty != NULL)
			(*sw_counters_info->dirty)++;
		sw_counters_info = sw_counters_info->parent;
	}

	return 0;
/* cleanup */
cleanup_sw_counters_groups_buffer:
	kfree(sw_counters_info->sw_counters.groups);
	sw_counters_info->sw_counters.groups = NULL;
cleanup_sw_counters_bin_file:
	release_bin_file(sw_counters_info->kobj, &sw_counters_info->bin_file);
cleanup_sw_counters_description_data:
	kfree(sw_counters_info->bin_file.info_buf);
cleanup_sw_counters_kobj:
	if (!sw_counters_info->parent)
		kfree(sw_counters_info->gen_sync_attr);
	if (sw_counters_info->kobj_owner)
		kobject_put(sw_counters_info->kobj);
cleanup_sw_counters_info:
	kfree(sw_counters_info);
	*hNewInfo = NULL;
	return ret;
}

int sph_remove_sw_counters_info_node(void *hInfoNode)
{
	struct sph_internal_sw_counters *sw_counters_info = (struct sph_internal_sw_counters *)hInfoNode;
	struct sph_internal_sw_counters *tmp_sw_counters_info = sw_counters_info;

	if (sw_counters_info->parent) {
		mutex_lock(&sw_counters_info->parent->list_lock);
		list_del(&sw_counters_info->node);
		mutex_unlock(&sw_counters_info->parent->list_lock);
	}

	remove_group_files(sw_counters_info);
	release_bin_file(sw_counters_info->kobj, &sw_counters_info->bin_file);

	/* remove gen sync attribute if root info node */
	if (!sw_counters_info->parent &&
	    sw_counters_info->gen_sync_attr) {
		remove_stale_bin_files(sw_counters_info->gen_sync_attr, 0, true);
		sysfs_remove_file(sw_counters_info->kobj,
				  &sw_counters_info->gen_sync_attr->attr);
		kfree(sw_counters_info->gen_sync_attr);
	}

	if (sw_counters_info->kobj_owner)
		kobject_put(sw_counters_info->kobj);

	kfree(sw_counters_info->sw_counters.groups);

	/* update root node dirty info, in case of early deletion of info object */
	while (tmp_sw_counters_info) {
		if (tmp_sw_counters_info->parent == NULL &&
		    tmp_sw_counters_info->dirty != NULL)
			(*tmp_sw_counters_info->dirty)++;
		tmp_sw_counters_info = tmp_sw_counters_info->parent;
	}


	mutex_destroy(&sw_counters_info->list_lock);
	kfree(sw_counters_info);

	return 0;
}

int sph_create_sw_counters_values_node(void *hInfoNode,
				    u32 node_id,
				    struct sph_sw_counters *parentSwCounters,
				    struct sph_sw_counters **counters)
{
	int ret;

	struct sph_internal_sw_counters   *sw_counters_info =
		(struct sph_internal_sw_counters *)hInfoNode;

	struct sph_internal_sw_counters *sw_counters_parent = NULL;
	struct sph_internal_sw_counters *sw_counters_values;

	char *dir_name = NULL;
	struct kobject *kobj;

	struct bin_stale_node *stale_node = NULL;
	bool   dir_exist = false;

	u32 counters_size;
	u32 n;

	mutex_lock(&values_tree_sync_mutex);

	counters_size = sw_counters_info->counters_set->counters_count * SPH_COUNTER_SIZE;

	sw_counters_values = kzalloc(sizeof(*sw_counters_values), GFP_KERNEL);
	if (!sw_counters_values) {
		sph_log_err(GENERAL_LOG, "unable to generate sph_sw_counters_object\n");
		mutex_unlock(&values_tree_sync_mutex);
		return -ENOMEM;
	}

	if (parentSwCounters)
		sw_counters_parent = SW_COUNTERS_TO_INTERNAL(parentSwCounters);

	/* set parent node */
	sw_counters_values->parent = sw_counters_parent;

	/* set pointer to info root */
	sw_counters_values->gen_sync_attr =
		sw_counters_info->gen_sync_attr;

	kobj = sw_counters_info->kobj;

	if (sw_counters_values->parent) {
		struct kobj_node *kobj_node;

		if (sw_counters_values->parent->kobj_owner) {
			kobj = NULL;
			mutex_lock(&sw_counters_values->parent->list_lock);
			list_for_each_entry(kobj_node, &sw_counters_values->parent->kobject_list, node) {
				if (strcmp(kobj_node->kobj->name, sw_counters_info->counters_set->name) == 0) {
					kobj = kobj_node->kobj;
					break;
				}
			}
			mutex_unlock(&sw_counters_values->parent->list_lock);

			/* in case it was not allocated before (new instance of info node)- we will create required directory */
			if (!kobj) {
				struct kobj_node *new_kobj = kzalloc(sizeof(*new_kobj), GFP_KERNEL);
				const char *name = sw_counters_info->counters_set->name;

				if (!new_kobj) {
					sph_log_err(GENERAL_LOG, "unable to allocate kernel object\n");
					ret = -ENOMEM;
					goto cleanup_sw_counters_values;
				}
				new_kobj->kobj = kobject_create_and_add(name, kobj);
				if (!new_kobj->kobj) {
					kfree(new_kobj);
					sph_log_err(GENERAL_LOG, "unable to create dirname for counters values - %s\n", name);
					ret = -ENOMEM;
					goto cleanup_sw_counters_values;
				}
				mutex_lock(&sw_counters_values->parent->list_lock);
				list_add_tail(&new_kobj->node, &sw_counters_values->parent->kobject_list);
				mutex_unlock(&sw_counters_values->parent->list_lock);
				kobj = new_kobj->kobj;
			}
		}
	}

	sw_counters_values->counters_set = sw_counters_info->counters_set;

	/* in case counters set is set as perID , driver will create a directory with node_id*/
	if (sw_counters_info->counters_set->perID) {
		u32 alloc_size = 1; // 1 for NULL terminating char

		alloc_size += snprintf(NULL, 0, "%u", node_id);
		dir_name = kmalloc_array(alloc_size, sizeof(char), GFP_KERNEL);
		if (dir_name == NULL) {
			sph_log_err(GENERAL_LOG, "unable to allocate buffer for dir name\n");
			ret = -ENOMEM;
			goto cleanup_sw_counters_values;
		}
		sprintf(dir_name, "%u", node_id);

		/* before creating a dir, check if it exist */
		spin_lock(&sw_counters_info->gen_sync_attr->lock);
		list_for_each_entry(stale_node,
				    &sw_counters_info->gen_sync_attr->stale_list,
				    node) {
			if (stale_node->kobj->parent == kobj &&
			    !strcmp(kobject_name(stale_node->kobj), dir_name)) {
				sw_counters_values->kobj = kobject_get(stale_node->kobj);
				dir_exist = true;
				break;
			}
		}
		spin_unlock(&sw_counters_info->gen_sync_attr->lock);

		/* create the dir if not found */
		if (!sw_counters_values->kobj)
			sw_counters_values->kobj = kobject_create_and_add(dir_name, kobj);
		if (!sw_counters_values->kobj) {
			sph_log_err(GENERAL_LOG, "unable to create kobject directory for %s\n", dir_name);
			ret = -ENOMEM;
			goto cleanup_sw_counters_values_dir_name;
		}
		kobj = sw_counters_values->kobj;
		sw_counters_values->kobj_owner = true;
		/* clean allocated dir_name */
		kfree(dir_name);
	}


	sw_counters_values->kobj = kobj;

	/* increment counters size ( first u64 is used for management ) */
	/* n case of root ( we will use 2 u64 for management ) */
	if (sw_counters_values->parent)
		counters_size += SPH_COUNTER_SIZE;
	else
		counters_size += 2 * SPH_COUNTER_SIZE;


	/* define counters values - this is a readonly binary file */
	sw_counters_values->bin_file.attr.attr.name	= "values";
	sw_counters_values->bin_file.attr.attr.mode	= 0444;
	sw_counters_values->bin_file.attr.mmap	= mmap_sph_counter_bin_values;
	sw_counters_values->bin_file.attr.read	= read_sph_counter_bin_values;
	sw_counters_values->bin_file.info_buf	= NULL;
	sw_counters_values->bin_file.info_size	= 0x0;

	/* create binary file for values - function will allocated pages*/
	ret = create_sph_bin_file(kobj, &sw_counters_values->bin_file, counters_size);
	if (ret) {
		sph_log_err(GENERAL_LOG, "unable to create sw_counters values file\n");
		goto cleanup_sw_counters_kobj;
	}

	/* in case counters_set are set as per ID driver will also allocate groups directory for enable/disable counters */
	if (sw_counters_info->counters_set->perID) {
		sw_counters_values->sw_counters.groups =
			kmalloc_array(sw_counters_info->counters_set->groups_count,
				      sizeof(u32),
				      GFP_KERNEL | __GFP_ZERO);
		if (!sw_counters_values->sw_counters.groups) {
			sph_log_err(GENERAL_LOG, "unable to allocate sw_counter groups array\n");
			ret = -ENOMEM;
			goto cleanup_sw_counters_bin_file;
		}
		ret = create_group_files(kobj, sw_counters_values, sw_counters_values->sw_counters.groups);
		if (ret)
			goto cleanup_sw_counters_groups_buffer;

		sw_counters_values->sw_counters.global_groups = sw_counters_info->sw_counters.groups;
	} else {
		sw_counters_values->sw_counters.groups = sw_counters_info->sw_counters.groups;
		sw_counters_values->sw_counters.global_groups = sw_counters_info->sw_counters.groups;
	}

	/* initialize global list of buffer descriptions */
	INIT_LIST_HEAD(&sw_counters_values->kobject_list);
	mutex_init(&sw_counters_values->list_lock);

	/* in case this is a new counter set perID driver will allocate all required directories set in info file */
	if (sw_counters_info->counters_set->perID) {
		struct sph_internal_sw_counters *infoNode;

		mutex_lock(&sw_counters_info->list_lock);
		if (dir_exist) {
			struct kobj_node *kobj_node;

			SW_COUNTERS_ASSERT(stale_node != NULL);
			list_for_each_entry(kobj_node, &stale_node->kobject_list, node) {
				struct kobj_node *new_kobj = kzalloc(sizeof(*new_kobj), GFP_KERNEL);

				if (new_kobj == NULL) {
					sph_log_err(GENERAL_LOG, "unable to allocate memory for new_kobj\n");
					ret = -ENOMEM;
					mutex_unlock(&sw_counters_info->list_lock);
					goto cleanup_sw_counters_children_kobject_list;
				}
				new_kobj->kobj = kobject_get(kobj_node->kobj);

				mutex_lock(&sw_counters_values->list_lock);
				list_add_tail(&new_kobj->node, &sw_counters_values->kobject_list);
				mutex_unlock(&sw_counters_values->list_lock);
			}
		} else {
			list_for_each_entry(infoNode, &sw_counters_info->children_List, node) {
				const char *name = infoNode->counters_set->name;
				struct kobj_node *new_kobj = kzalloc(sizeof(*new_kobj), GFP_KERNEL);

				if (new_kobj == NULL) {
					sph_log_err(GENERAL_LOG, "unable to allocate memory for new_kobj\n");
					ret = -ENOMEM;
					mutex_unlock(&sw_counters_info->list_lock);
					goto cleanup_sw_counters_children_kobject_list;
				}

				new_kobj->kobj = kobject_create_and_add(name, kobj);

				mutex_lock(&sw_counters_values->list_lock);
				list_add_tail(&new_kobj->node, &sw_counters_values->kobject_list);
				mutex_unlock(&sw_counters_values->list_lock);
			}
		}
		mutex_unlock(&sw_counters_info->list_lock);
	}

	/* set counters values, in case of global counters we save the first value for updates in case of new object*/
	sw_counters_values->sw_counters.values = ((u64 *)page_address(sw_counters_values->bin_file.bin_page));

	/* set values dirty */
	sw_counters_values->dirty = sw_counters_values->sw_counters.values;
	sw_counters_values->sw_counters.values++;

	/* if this is root directory - we will add another counter for dirty info file (create/destroy) */
	if (sw_counters_values->parent == NULL) {
		sw_counters_info->dirty = sw_counters_values->sw_counters.values;
		/* save dirty info pointer - in case of values removal - we will */
		/* need to set this pointer to NULL */
		sw_counters_values->info_node = sw_counters_info;
		sw_counters_values->sw_counters.values++;
	}


	/* initialize spinlocks for atomic counters update */
	n = counters_size / SPH_COUNTER_SIZE;
	if (n > 0) {
		sw_counters_values->sw_counters.spinlocks = kmalloc_array(n,
									  sizeof(spinlock_t),
									  GFP_KERNEL);
		if (sw_counters_values->sw_counters.spinlocks == NULL) {
			sph_log_err(GENERAL_LOG, "unable to allocate memory for spinlocks\n");
			ret = -ENOMEM;
			goto cleanup_sw_counters_children_kobject_list;
		}

		do {
			n--;
			spin_lock_init(&sw_counters_values->sw_counters.spinlocks[n]);
		} while (n > 0);
	} else {
		sw_counters_values->sw_counters.spinlocks = NULL;
	}

	/* set the external buffer to user */
	*counters = &(sw_counters_values->sw_counters);


	/* once new object was created we will update node to root */
	while (sw_counters_values != NULL) {
		(*sw_counters_values->dirty)++;
		sw_counters_values = sw_counters_values->parent;
	}

	mutex_unlock(&values_tree_sync_mutex);

	return 0;

cleanup_sw_counters_children_kobject_list:
if (sw_counters_info->counters_set->perID) {
	struct kobj_node *kobjNode;
	/* cleanup child directories*/
	mutex_lock(&sw_counters_values->list_lock);
	while (!list_empty(&sw_counters_values->kobject_list)) {
		kobjNode = list_first_entry(&sw_counters_values->kobject_list, struct kobj_node, node);
		list_del(&kobjNode->node);
		kobject_put(kobjNode->kobj);
		kfree(kobjNode);
	}
	mutex_unlock(&sw_counters_values->list_lock);
}
cleanup_sw_counters_groups_buffer:
	kfree(sw_counters_values->sw_counters.groups);
cleanup_sw_counters_bin_file:
	release_bin_file(kobj, &sw_counters_values->bin_file);
cleanup_sw_counters_kobj:
	if (sw_counters_values->kobj_owner)
		kobject_put(sw_counters_values->kobj);
cleanup_sw_counters_values_dir_name:
	kfree(dir_name);
cleanup_sw_counters_values:
	kfree(sw_counters_values);

	mutex_unlock(&values_tree_sync_mutex);

	return ret;
}


int sph_sw_counters_release_values_node(struct sph_internal_sw_counters *sw_counters_values)
{
	bool bGroupsOwner = (sw_counters_values->groups_kobj != NULL);
	struct sph_internal_sw_counters *tmp_sw_counters_values = sw_counters_values;
	struct kobj_node *kobjNode;
	u64 root_dirty = 0;

	mutex_lock(&values_tree_sync_mutex);

	/* once new object was deleted we will update node to root */
	while (tmp_sw_counters_values->parent != NULL) {
		++(*tmp_sw_counters_values->dirty);
		tmp_sw_counters_values = tmp_sw_counters_values->parent;
	}
	root_dirty = ++(*tmp_sw_counters_values->dirty);



	remove_group_files(sw_counters_values);


	/* in case removing root values node - driver need to clean dirty info pointer */
	/* so, info dirty counter will stop getting updated */
	/* this can happen only when driver unloaded */
	if (sw_counters_values->parent == NULL) {
		if (sw_counters_values->info_node != NULL)
			sw_counters_values->info_node->dirty = NULL;
	}

	/*
	 * if gen sync clients exist then
	 * we create a stale copy instead of removing the attribute file
	 * to let all clients get a chance to map and read it.
	 */
	if (gen_sync_has_clients(sw_counters_values->gen_sync_attr)) {
		mutex_lock(&sw_counters_values->list_lock);
		move_to_stale_list(sw_counters_values->gen_sync_attr,
				   sw_counters_values->kobj,
				   &sw_counters_values->bin_file,
				   &sw_counters_values->kobject_list,
				   root_dirty);
		mutex_unlock(&sw_counters_values->list_lock);
	} else {
		release_bin_file(sw_counters_values->kobj,
				 &sw_counters_values->bin_file);
	}

	/* cleanup child directories*/
	mutex_lock(&sw_counters_values->list_lock);
	while (!list_empty(&sw_counters_values->kobject_list)) {
		kobjNode = list_first_entry(&sw_counters_values->kobject_list,
					    struct kobj_node, node);
		list_del(&kobjNode->node);
		kobject_put(kobjNode->kobj);
		kfree(kobjNode);
	}
	mutex_unlock(&sw_counters_values->list_lock);

	if (sw_counters_values->kobj_owner)
		kobject_put(sw_counters_values->kobj);


	if (bGroupsOwner)
		kfree(sw_counters_values->sw_counters.groups);

	kfree(sw_counters_values->sw_counters.spinlocks);

	mutex_destroy(&sw_counters_values->list_lock);
	kfree(sw_counters_values);

	mutex_unlock(&values_tree_sync_mutex);

	return 0;


}

int sph_remove_sw_counters_values_node(struct sph_sw_counters *counters)
{
	struct sph_internal_sw_counters *sw_counters_values;

	sw_counters_values = SW_COUNTERS_TO_INTERNAL(counters);

	sph_sw_counters_release_values_node(sw_counters_values);


	return 0;
}
