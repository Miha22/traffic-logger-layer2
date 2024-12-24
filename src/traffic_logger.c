#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <traffic_logger.h>

static struct nf_hook_ops nf_netdev_hook;
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

static struct rhashtable frames_info;

unsigned int traffic_netdev_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct ethhdr* pHdr = eth_hdr(skb);  
    if(!pHdr) {
        printk(KERN_WARNING "failed to capture ethernet header in traffic_logger module.");
        return NF_ACCEPT;
    }
    uint32_t proto_hs = ntohs(pHdr->h_proto);

    if(!whitelist_proto[proto_hs]) {
        return NF_ACCEPT;//skipping uninterested packet O(1)
    }

    unsigned char source_mac[ETH_ALEN];
    memcpy(source_mac, pHdr->h_source, ETH_ALEN);
    uint32_t hash = jhash(source_mac, ETH_ALEN, 0);

    //to be continued working with rhashtable...

    return NF_ACCEPT;
}

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