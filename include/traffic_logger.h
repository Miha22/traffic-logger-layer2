#pragma once

#include <linux/rhashtable.h>
#include <linux/etherdevice.h>
#include <linux/ip.h> 

#define BUF_SIZE 1000
#define WORKERS_SIZE BUF_SIZE / BATCH_SIZE
#define MAC_SIZE 18 // 11 22 33 44 55 66 = 12 + 5 + 1 = 18 chars

struct mac_info {
	int key;
    unsigned char src_mac[ETH_ALEN];
	struct rhash_head linkage;
	// uint32_t counter;
	refcount_t ref;
	struct rcu_head rcu_read;
};

struct mac_list {
	unsigned char *arr[BUF_SIZE];
	uint32_t len;
}

struct packet_info {
	struct ethhdr eth_h;
	//struct iphdr ip_h;
}

struct work_info {
    struct work_struct work;
    int cpu_id;
	int batch_start;
};

static int wq_process_dump(struct work_struct *work_ptr);
static void clear_slab_caches(void);