#pragma once

#include <linux/types.h>

#define WHITELIST_SIZE 65536
#define BUF_SIZE 1000
#define WORKERS_SIZE BUF_SIZE / BATCH_SIZE
#define MAC_SIZE 18 // 11 22 33 44 55 66 = 12 + 5 + 1 = 18 chars

struct mac_info {
	struct rhash_head linkage;
    unsigned char src_mac[ETH_ALEN];
	refcount_t ref;
	struct rcu_head r_head;
};//[  597.628502] object_params: key len=6, key offset=4, head offset=0

struct mac_list {
	unsigned char *arr[BUF_SIZE];
	uint32_t len;
};

struct packet_info {
	struct ethhdr eth_h;
	//struct iphdr ip_h;
};

struct work_info {
    struct work_struct work;
    int cpu_id;
	uint32_t batch_start;
};

static int wq_process_dump(struct work_struct *work_ptr);
static void clear_slab_caches(void);
void dump_htable(struct work_struct *work);