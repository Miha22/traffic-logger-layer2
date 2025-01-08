#pragma once

#include <linux/types.h>

#define BUF_SIZE 10000
#define BATCH_SIZE 100
#define WHITELIST_SIZE 65536
#define WORKERS_SIZE BUF_SIZE / BATCH_SIZE
#define MAC_SIZE 18

struct mac_info {
	unsigned char src_mac_key[ETH_ALEN];
	struct rhash_head linkage;
    unsigned char src_mac[ETH_ALEN];
	refcount_t ref;
	struct rcu_head rcu_read;
};

struct packet_info {
	struct ethhdr eth_h;
};

struct work_info {
    struct work_struct work;
    int cpu_id;
	uint32_t batch_start;
};

static int32_t whitelist_proto[WHITELIST_SIZE] = {
    [ETH_P_IP] = 1,
    [ETH_P_IPV6] = 1,
    [ETH_P_ARP] = 1,
    [ETH_P_RARP] = 1,
    [ETH_P_MPLS_UC] = 1,
    [ETH_P_MPLS_MC] = 1,
    [ETH_P_BATMAN] = 1,
    [ETH_P_LLDP] = 1,
    [ETH_P_8021Q] = 1,
    [ETH_P_PPP_DISC] = 1,
    [ETH_P_PPP_SES] = 1,
    [ETH_P_IPX] = 1,
    [ETH_P_ATALK] = 1,
    [ETH_P_AARP] = 1,
    [ETH_P_8021AD] = 1,
    [ETH_P_PROFINET] = 1,
    [ETH_P_FCOE] = 1,
    [ETH_P_MCTP] = 1,
    [ETH_P_TDLS] = 1,
    [ETH_P_1588] = 1,
    [ETH_P_NCSI] = 1,
    [ETH_P_MACSEC] = 1,
    [ETH_P_FIP] = 1,
};


static int wq_process_dump(struct work_struct *work_ptr);
static void clear_slab_caches(void);
static int packet_rcv(struct sk_buff *skb, struct net_device *dev,
                      struct packet_type *pt, struct net_device *orig_dev);
void dump_htable(struct work_struct *work);