#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/types.h>
#include <traffic_logger.h>
#include <linux/circ_buf.h>
#include <linux/slab.h>

#define BUF_SIZE 1024

static struct kmem_cache *packet_cache;
static struct nf_hook_ops nf_netdev_hook;
static struct rhashtable frames_info;
static int32_t whitelist_proto[65536] = {
    [ETH_P_IP] = 1,
    [ETH_P_IPV6] = 1,
    [ETH_P_ARP] = 1,
    [ETH_P_RARP] = 1,
    [ETH_P_MPLS_UC] = 1,
    [ETH_P_BATMAN] = 1,
    [ETH_P_LLDP] = 1,
};//2 bytes sacrifised for O(1) whitelist

const static struct rhashtable_params object_params = {
	.key_len     = sizeof(uint32_t),
	.key_offset  = offsetof(struct mac_info, key),
	.head_offset = offsetof(struct mac_info, linkage),
};

struct packet_info *new_packet_info(void) {
    return kmem_cache_alloc(packet_cache, GFP_ATOMIC);
}

void free_packet(struct packet_info *pkt) {
    kmem_cache_free(packet_cache, pkt);
}

void cleanup_packet_cache(void) {
    kmem_cache_destroy(packet_cache);
}

int init_packet_cache(void) {
    packet_cache = kmem_cache_create(
		"packet_cache",
		sizeof(struct packet_info), 
		0, 
		SLAB_HWCACHE_ALIGN, 
		NULL
	);

    if (!packet_cache) {
        printk(KERN_ERR "Failed to create slab cache for struct packet_info\n");
        return -ENOMEM;
    }

    return 1;
}

unsigned int traffic_netdev_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct ethhdr* eth_h = eth_hdr(skb);
    struct iphdr *ip_h = ip_hdr(skb);  

    if(!eth_h || !ip_h) {
        printk(KERN_INFO "failed to capture ethernet or ip header in traffic_logger module.");
        return NF_ACCEPT;
    }
    uint32_t proto_hs = ntohs(eth->h_proto);

    if(!whitelist_proto[proto_hs]) {
        return NF_ACCEPT;//skipping uninterested packet O(1)
    }

    struct packet_info *packet_info = new_packet_info();
    if (!packet_info) {
        printk(KERN_ERR "slab memory allocation failed in netfilter hook\n");
        return NF_ACCEPT;
    }

    memcpy(&packet_info->eth_h, eth_h, sizeof(struct ethhdr));
    memcpy(&packet_info->ip_h, ip_h, sizeof(struct iphdr));

    //slab


    return NF_ACCEPT;
}

    // unsigned char source_mac[ETH_ALEN];
    // memcpy(source_mac, eth->h_source, ETH_ALEN);
    // uint32_t hash = jhash(source_mac, ETH_ALEN, 0);

    //to be continued working with rhashtable...

static void init_hook(struct nf_hook_ops *nfho, 
                    unsigned int (*hook_cb)(void*, struct sk_buff*, const struct nf_hook_state *), 
                    uint8_t protocol, 
                    uint32_t routing, 
                    int32_t priority
                ) {
    nfho->hook = hook_cb;
    nfho->dev = NULL;
    nfho->pf = protocol;
    nfho->hooknum = routing;
    nfho->priority = priority;
}

static int __init logger_init(void) {
    uint32_t result = rhashtable_init(&my_objects, &object_params);
    if(!result) {
        printk(KERN_ERR "Error initing hashtable in logger_init\n");
        return -EINVAL;
    }
    init_hook(&nf_netdev_hook, traffic_netdev_hook, NFPROTO_NETDEV, NF_NETDEV_INGRESS, NF_IP_PRI_FIRST);

    printk(KERN_INFO "Traffic logger module loaded.\n");

    return 0;
}

static void __exit logger_exit(void) {

    printk(KERN_INFO "Traffic logger module UNloaded.\n");
}

module_init(logger_init);
module_exit(logger_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Den/M22");
MODULE_DESCRIPTION("Packet logger");