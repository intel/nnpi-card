/*******************************************************************************
 * INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2020 Intel Corporation. All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to the
 * source code ("Material") are owned by Intel Corporation or its suppliers or
 * licensors. Title to the Material remains with Intel Corporation or its suppliers
 * and licensors. The Material contains trade secrets and proprietary and
 * confidential information of Intel or its suppliers and licensors. The Material
 * is protected by worldwide copyright and trade secret laws and treaty provisions.
 * No part of the Material may be used, copied, reproduced, modified, published,
 * uploaded, posted, transmitted, distributed, or disclosed in any way without
 * Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery of
 * the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
 ********************************************************************************/

#pragma once

#include <string>
#include <stdint.h>
#include <memory>
#include <map>
#include <vector>
#include <set>
#include "um_shm_layout.h"

/**
 * @brief group_info
 *
 * There is one instance of this object for each group file in the
 * sw counters tree.
 */
class group_info {
public:
	typedef std::shared_ptr<group_info> ptr;
	typedef std::map<std::string, group_info::ptr> map;

	/**
	 * @brief creates a group_info instance from a group file name
	 */
	static group_info *create(const char *filename);

	/**
	 * @brief creates a group_info instance from mapped um shm group_val struct
	 */
	static group_info *create_um(uint32_t  group_idx,
				     uint32_t *group_enable_ptr,
				     sem_t    *lock_ptr);

	/**
	 * @brief check if the group is enabled
	 */
	bool is_enabled(void) const
	{
		return m_enabled;
	};

	/**
	 * @brief set the group as enable or disable
	 *
	 * The set_enable function increment or decrement the enable
	 * count of the group. The enable state is propogated to the sw
	 * counter file only when the enable count changes from 0 to 1 or
	 * from 1 to 0.
	 */
	bool set_enable(bool enable);

	const std::string &filename(void) const
	{
		return m_filename;
	}

	uint32_t get_index(void)
	{
		return m_shm_group_idx;
	}

private:
	/**
	 * @brief protected constructor, create only through the create function
	 */
	explicit group_info(const char *filename, int enabled) :
				m_shm_group_idx(-1),
				m_shm_enable_count(nullptr),
				m_shm_lock_sem(nullptr),
				m_enabled(enabled)
	{
		if (filename)
			m_filename = std::string(filename);
	};

	explicit group_info(uint32_t  shm_group_idx,
			    uint32_t *group_enable_ptr,
			    sem_t    *lock_sem,
			    int enabled) :
				m_shm_group_idx(shm_group_idx),
				m_shm_enable_count(group_enable_ptr),
				m_shm_lock_sem(lock_sem),
				m_enabled(enabled)
	{ };

private:
	std::string m_filename;
	uint32_t    m_shm_group_idx;
	uint32_t   *m_shm_enable_count;
	sem_t      *m_shm_lock_sem;
	int         m_enabled;
};


/**
 * @brief counter_info
 *
 * Holds single sw counter information.
 */
struct counter_info {
	typedef std::shared_ptr<counter_info> ptr;
	typedef std::map<std::string, counter_info::ptr> map;

	uint32_t        m_offset;
	bool            m_restricted;
	group_info::ptr m_group;
	std::string     m_group_name;
	std::string     m_description;
};

/**
 * @brief counter_info_set
 *
 * A map between a counter name and its info details.
 */
typedef std::map<std::string, counter_info::ptr> counter_info_set;

/**
 * @brief counters_info_node
 *
 * There is one instance of this object for each info or info.perID file in
 * the sw counters tree.
 * It holds the list of counter and group information.
 */
class counters_info_node {
public:
	typedef std::shared_ptr<counters_info_node> ptr;
	typedef std::map<std::string, counters_info_node::ptr> map;

	/**
	 * @brief loads an entire tree of sw counter info files.
	 *
	 * Loads all info and info.perID files exist in the filesystem
	 * under the given directory name.
	 * Generate a counters_info_node instance for each file, keeping the
	 * hierarchy as observed in the file system.
	 * Returns a pointer to the info node of the root.
	 */
	static counters_info_node *load_tree(const char             *dirname);

	static counters_info_node *load_um_tree(const char *name);

	~counters_info_node();

	/**
	 * @brief retreives a list of all counters described in the info file
	 */
	void get_counter_set(counter_info_set &out_set,
			     std::string       base_name = "",
			     bool recursive = true);

	/**
	 * @brief Check if the counters of this info object are perID or not
	 */
	bool isPerID(void) const
	{
		return m_perID;
	}

	/**
	 * @brief returns the number of counters of that info object
	 */
	int get_num_counters(void) const
	{
		return ((int)m_counters.size());
	}

	int get_num_groups(void) const
	{
		return ((int)m_groups.size());
	}

	/**
	 * @brief look-up an immediate info child in the hierarchy by name
	 */
	counters_info_node::ptr find_child(const std::string &name);

	/**
	 * @brief retrieve a reference to the counters info map
	 */
	const counter_info::map &get_info_map(void) const
	{
		return m_counters;
	};

	/**
	 * @brief retrieve counter info for one single counter by name
	 */
	counter_info::ptr get_counter_info(const std::string &name)
	{
		counter_info::map::iterator i(m_counters.find(name));
		if (i != m_counters.end())
			return (*i).second;
		else
			return counter_info::ptr(nullptr);
	};

	/**
	 * @brief retrieve a pointer to a group file object by name
	 */
	group_info::ptr get_group_info(const std::string &name)
	{
		group_info::map::iterator i(m_groups.find(name));
		if (i != m_groups.end())
			return (*i).second;
		else
			return group_info::ptr(nullptr);
	}

	const struct um_shm_counters_set *get_shm_set(void)
	{
		return m_shm_set;
	}

	char *get_values_shm_name(void)
	{
		if (m_shm_set)
			return m_shm_set->values_shm_name;

		return nullptr;
	}

	bool is_um_info(void) const
	{
		return m_shm_set != nullptr;
	}

	const counters_info_node::map &childs(void)
	{
		return m_childs;
	}

	const group_info::map &groups_map(void)
	{
		return m_groups;
	};

	const uint32_t child_idx(void)
	{
		return m_um_child_idx;
	};

private:
	explicit counters_info_node();
	bool load_info_file(const char *filename);
	void read_um_sw_counters_set(const char   *root_ptr,
				     const char  *&ptr,
				     const char  **out_name);

	static void traverse_cb(const std::string &dirpath,
				const std::string &dirname,
				void              *ctx);

private:
	bool                                 m_perID;
	void                                *m_shm_ptr;
	size_t                               m_shm_size;
	struct um_shm_counters_set          *m_shm_set;
	uint32_t                             m_um_child_idx;
	counter_info::map                    m_counters;
	group_info::map                      m_groups;
	counters_info_node::map              m_childs;
};

struct shm_values_map_info {
	typedef std::shared_ptr<shm_values_map_info> ptr;

	shm_values_map_info(char *ptr, size_t size) :
		shm_ptr(ptr),
		shm_size(size)
	{
	}

	~shm_values_map_info();

	char                           *shm_ptr;
	size_t                          shm_size;
};

typedef std::vector<shm_values_map_info::ptr> shm_map_vec;

/**
 * @brief counters_values
 *
 * There is one instance of this object for each values file in
 * the sw counters tree.
 * It holds a pointer to an mmapped buffer of the values as well as
 * a pointer to the corresponding info and group nodes relavant for this
 * values object
 */
class counters_values {
public:
	typedef std::shared_ptr<counters_values> ptr;
	typedef std::map<int, counters_values::ptr> map;

	/**
	 * @brief creates a tree of all values objects
	 *
	 * Creates an object for a values file.
	 * The info_node parameter should be a the info node related to the
	 * values file in the sw counters filesystem tree.
	 *
	 * Returns a pointer to the values object of the root node.
	 */
	static counters_values *create(const std::string      &val_fname,
				       const std::string      &groups_dirname,
				       counters_info_node::ptr info_node,
				       bool                    is_stale = false,
				       int                     orig_obj_id = -1);

	static counters_values *create_um(counters_info_node::ptr     info_node,
                                          struct um_shm_values_block *block,
                                          shm_values_map_info::ptr    block_map);

	~counters_values();

	/**
	 * @brief retreive the info node associated with that values node
	 */
	const counter_info::map &get_info_map(void) const
	{
		return m_info_node->get_info_map();
	};

	/**
	 * @brief get a pointer to the start of the values buffer
	 */
	const uint64_t *values(void) const
	{
		return m_values;
	};

	/**
	 * @brief get a pointer to a counter given its offset
	 */
	const uint64_t *get_ptr(uint32_t offset) const
	{
		return (const uint64_t *)((uintptr_t)m_values + offset);
	};

	bool is_stale(void) const
	{
		return m_is_stale;
	};

	char *child_shm_name(uint32_t child_idx)
	{
		if (!m_child_shm_names)
			return nullptr;
		else return &m_child_shm_names[UM_SHM_NAME_SIZE * child_idx];
	};

	int orig_obj_id(void) const { return m_orig_obj_id; }

private:
	counters_values(counters_info_node::ptr info_node,
			const uint64_t         *values,
			bool                    is_stale,
			int                     orig_obj_id);

private:
	const counters_info_node::ptr m_info_node;
	struct um_shm_values_block   *m_shm_block;
	shm_values_map_info::ptr      m_shm_block_map;
	char                         *m_child_shm_names;
	const uint64_t               *m_values;
	const bool                    m_is_stale;
	group_info::map               m_groups;
	int                           m_orig_obj_id;
};

/**
 * @brief counters_values_vec
 *
 * Holds either a single counters_values object or a vector of
 * counters_values objects in case of "perID" values.
 * The counters_values object of a specific object id (in the perID case)
 * can be retreived using its object id.
 */
class counters_values_vec {
public:
	typedef std::shared_ptr<counters_values_vec> ptr;

	/**
	 * @brief instanciate a "non-perID" instance of counters_values_vec
	 */
	explicit counters_values_vec(counters_values::ptr vals);

	/**
	 * @brief instanciate a "perID" instance of counters_values_vec
	 */
	explicit counters_values_vec();

	/**
	 * @brief sets the counters_values object of specific object id
	 */
	bool set_values(uint32_t id, counters_values::ptr vals);

	/**
	 * @brief retrieve a pointer to one counters_values object
	 */
	counters_values::ptr get_values(uint32_t id = 0)
	{
		if (m_vals.get() != nullptr)
			return m_vals;
		else
			return m_per_id_vals[id];
	};

	/**
	 * @brief retrieve a reference to a id->values map of all existing object ids.
	 */
	const counters_values::map &get_map(void) const
	{
		return m_per_id_vals;
	};

private:
	const counters_values::ptr m_vals;
	counters_values::map m_per_id_vals;
};

typedef std::pair<counters_values::ptr, counter_info::ptr> values_info_pair;
typedef std::map<std::string, values_info_pair> counter_values_offset_map;
typedef std::pair<std::string, const uint64_t *> name_ptr_pair;
typedef std::vector<name_ptr_pair> counters_vec;

/**
 * @brief counters_values_node
 *
 * There is one instance of this object for each values file in
 * the sw counters tree.
 * It holds a pointer to a counters_values object loaded for a values file
 * and to the counters_values to all it children in the hierarchy.
 */
class counters_values_node {
public:
	typedef std::shared_ptr<counters_values_node> ptr;
	typedef std::map<std::string, counters_values_node::ptr> map;

	/**
	 * @brief creates a tree of all values node objects
	 *
	 * Creates objects for all values file exist under the directory
	 * tree starts at the given dirpath. The info_node parameter should
	 * be a pointer to the info node loaded from dirpath.
	 *
	 * Returns a pointer to the values node object of the root node.
	 */
	static counters_values_node *load_tree(const char *dirname,
					       counters_info_node::ptr info);

	~counters_values_node();

	/**
	 * @brief loads all stale value files under the values node
	 */
	void load_stale_values(const std::string       dirpath,
			       counters_info_node::ptr info,
			       int                     orig_obj_id);

	/**
	 * @brief loads out_map with name->(values, offset) info.
	 *
	 * loads the mapping data for the entire values tree under this node
	 * if recursive is true, otherwise loads the mapping info only for
	 * the counters of this values node only.
	 */
	void get_values_map(counter_values_offset_map &out_map,
			    std::string                base_name = "",
			    bool                       recursive = true,
			    uint32_t                  *out_stale_count = nullptr);

	/**
	 * @brief find a pointer to a counter by name (no wildcards)
	 */
	const uint64_t *find_counter(const std::string &name);

private:
	counters_values_node(counters_info_node::ptr info) :
		m_info(info)
	{};

	static void traverse_cb(const std::string &dirpath,
				const std::string &dirname,
				void              *ctx);

	bool load_um_tree(const char *shm_name = nullptr);

	typedef std::map<int, counters_values_node::map>         map_vec;

private:
	const counters_info_node::ptr   m_info;
	counters_values_vec::ptr        m_values;
	counters_values_node::map       m_childs;
	counters_values_node::map_vec   m_childs_vec;
	shm_map_vec                     m_shm_maps;
};

typedef std::set<counters_values::ptr> values_set;
typedef std::set<group_info::ptr> groups_set;

bool counters_wild_match(const std::string &val,
			 const std::string &match_str,
			 size_t             val_pos = 0,
			 size_t             match_pos = 0);

/**
 * @brief counters_tree
 *
 * This object represent a full sw counters filesystem tree starts from
 * one root directory which includes info and values files and may have
 * child directories trees below it with a full hierarchy counters.
 * It holds both the info and values trees of the counters.
 */
class counters_tree {
public:
	typedef std::shared_ptr<counters_tree> ptr;
	typedef std::vector<counters_tree::ptr> vec;

	typedef bool (*extra_filter_func)(const std::string       &name,
					  const counter_info::ptr info,
					  void                   *ctx);

	/**
	 * @brief creates a tree of all info AND values node objects
	 *
	 * Creates objects for all info and values files exist under the
	 * directory specified by dirname,
	 * base_name can be used to add a prefix to the counter names under
	 * that tree.
	 *
	 * Returns a pointer to the root tree object.
	 */
	static counters_tree *create(const std::string &dirname,
				     const std::string &base_name = std::string(""));

	static counters_tree *create_um(const char *name,
					const std::string &base_name);

	/**
	 * @brief retreived counter info for all counters under that tree.
	 */
	const counter_info_set &get_counter_set(void)
	{
		if (should_update_info())
			update_values_set(false);
		return m_counter_set;
	};

	/**
	 * @brief find all existing counter values matching a wildcard.
	 *
	 * This function takes a wildcard string of a counter name, the
	 * asterix character can be used in that string to match any
	 * sub-string in a counter name.
	 * The function filters from all existing counter values in the
	 * tree the counters which their names matching the given wildcard.
	 * If update parameter is true then the list of all existing counter
	 * values will be refreshed by re-scanning the directoy tree.
	 * The return value of the function is the number of matching counter
	 * values, the function also has the following outputs:
	 * out_vec - a vector of <name, const uint64_t *> pairs containing
	 *           the counter name and a pointer to its value.
	 *           The function does not clear out_vec, it only adds into it
	 *           the information for all matching counters.
	 * unique_names - a set of counter names that should be ignored for the
	 *                match. The matched counter names are added to this
	 *                set. This is used to avoid duplicate counters in a
	 *                report.
	 * out_values_set - a set of all counters_values objects which has at
	 *                  least one counter value which matched the filter.
	 *                  The function does not clear out_values_set, it
	 *                  only inserts new values to it.
	 * out_groups_set - a set of all group objects which has at least one
	 *                  counter value which matched the filter.
	 *                  The function does not clear out_groups_set, it
	 *                  only inserts new values to it.
	 */
	uint32_t filter_values_set(const std::string  &match_str,
				   std::set<std::string> &unique_names,
				   counters_vec       &out_vec,
				   values_set         &out_values_set,
				   groups_set         &out_groups_set,
				   extra_filter_func   filter_func = nullptr,
				   void               *filter_ctx = nullptr,
				   bool                update = false);

	/**
	 * @breif find all global groups node referenced by a wildcard
	 *
	 * The function look up all groups hidden behind an asterics in
	 * a counter name wildcard given in match_str.
	 * If match_str does not include the '*' character then the function
	 * will match no groups.
	 * The function returns the number of matched counters and the set
	 * of global group pointers.
	 */
	uint32_t match_dynamic_groups(const std::string  &match_str,
				      groups_set         &out_groups_set,
				      bool                update = false);
	/**
	 * @brief find a pointer to a counter by name (no wildcards)
	 */
	const uint64_t *find_counter(const std::string &name)
	{
		if (m_values.get() != nullptr)
			return m_values->find_counter(name);

		return nullptr;
	};

	const bool should_update_values(bool is_auto_refresh) const {
		return (!is_auto_refresh && m_num_stale_objects > 0) ||
			!m_dirty_values_ptr ||
			*m_dirty_values_ptr != m_last_dirty_values;
	};

	const bool should_update_info() const {
		return (m_dirty_info_ptr &&
			m_last_dirty_info != *m_dirty_info_ptr);
	};

	bool update_values_set(bool force,
			       bool is_auto_refresh = false);

	const std::string &dirname(void) const
	{
		return m_dirname;
	};

	uint64_t last_values_refresh(void) const
	{
		return m_last_dirty_values;
	};

	bool is_um_tree(void)
	{
		return m_info.get() != nullptr &&
		       m_info->is_um_info();
	}

	uintptr_t create_sync_handle(void);
	void      destroy_sync_handle(uintptr_t sync_handle);
	void      sync_handle_refreshed(uintptr_t sync_handle);

private:
	counters_tree(const std::string &dirname,
		      const std::string &base_name) :
		m_dirname(dirname),
		m_base_name(base_name),
		m_num_stale_objects(0),
		m_dirty_info_ptr(nullptr),
		m_dirty_values_ptr(nullptr),
		m_last_dirty_info(-1),
		m_last_dirty_values(0)
	{
	};

private:
	const std::string         m_dirname;
	const std::string         m_base_name;
	counters_info_node::ptr   m_info;
	counter_info_set          m_counter_set;
	counters_values_node::ptr m_values;
	counter_values_offset_map m_values_map;
	uint32_t                  m_num_stale_objects;
	const uint64_t           *m_dirty_info_ptr;
	const uint64_t           *m_dirty_values_ptr;
	uint64_t                  m_last_dirty_info;
	uint64_t                  m_last_dirty_values;
};
