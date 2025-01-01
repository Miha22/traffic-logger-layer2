#pragma once

#include <linux/rhashtable.h>
#include <linux/etherdevice.h>
#include <linux/ip.h> 

#define BUF_SIZE 1000

struct data_info {
	uint32_t key;
    char mac_s[ETH_ALEN];
	struct rhash_head linkage;
	uint32_t counter;
	refcount_t ref;
	struct rcu_head rcu_read;
};

struct data_block {
    unsigned char src_mac[ETH_ALEN];
	unsigned char dst_mac[ETH_ALEN];
	__be32 src_ip;
	__be32 dst_ip;
};

struct packet_info {
	struct ethhdr eth_h;
	struct iphdr ip_h;
}

struct work_info {
    struct work_struct work;
    int cpu_id;
};