#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

#include <linux/slab.h>
#include <linux/workqueue.h>  
#include <linux/percpu.h>
#include <linux/kfifo.h>

#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/wait.h>

#include <linux/buffer.h>s
#include <traffic_logger.h>

#define WHITELIST_SIZE 65536
#define BUF_SIZE 1000
#define BATCH_SIZE 100

static struct rhashtable frames_info;
static struct kmem_cache *packet_cache;
static struct nf_hook_ops nf_netdev_hook;
static DECLARE_RWSEM(htable_semaphore);
static DEFINE_PER_CPU(struct kfifo, packet_mem_stack);
static DEFINE_PER_CPU(atomic_t, batch_counter);
static struct work_struct update_table_work;
static DECLARE_WAIT_QUEUE_HEAD(w_wait_queue);
atomic_t dumping_hashtable = ATOMIC_INIT(0);
//wake_up_all(&w_wait_queue); //notifyAll()
//wait_event(w_wait_queue, atomic_read(&dumping_hashtable) == 0);//thread.sleep()

static int32_t whitelist_proto[WHITELIST_SIZE] = {
    [ETH_P_IP] = 1,
    [ETH_P_IPV6] = 1,
    [ETH_P_ARP] = 1,
    [ETH_P_RARP] = 1,
    [ETH_P_MPLS_UC] = 1,
    [ETH_P_BATMAN] = 1,
    [ETH_P_LLDP] = 1,
};

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

int init_packet_memory(void) {//and batch_counter
    if(packet_cache == NULL) {
        printk(KERN_ERR "Cache must be initialized first\n");
        return -EPERM;
    }
    int cpu, ret;
    for_each_possible_cpu(cpu) {
        atomic_t *b_counter = &per_cpu(batch_counter, cpu);
        *b_counter = ATOMIC_INIT(0);

        struct kfifo *stack = &per_cpu(packet_mem_stack, cpu);
        ret = kfifo_alloc(stack, BUF_SIZE, GFP_KERNEL);
        if (ret) {
            printk(KERN_ERR "Failed to allocate kfifo per CPU:%d\n", cpu);
            return -ENOMEM;
        }
        for(uint16_t i = 0; i < BUF_SIZE; i++) {
            struct packet_info *p_info = new_packet_info();
            kfifo_in(stack, p_info, 1); 
        }
    }

    return 1;
}

void* get_packet_memory(struct kfifo *stack) {
    struct packet_info *p_info = NULL;

    if (!kfifo_is_empty(stack)) {
        kfifo_out(stack, &p_info, 1);
    }

    if (!p_info) {
        printk(KERN_ERR "[BUF_FULL] Failed to allocate memory for incoming packet, skipping\n");
        return NULL;
    }

    return p_info;
}

int free_packet_mem(struct kfifo *stack, void* packet_ptr) {
      if (!packet_ptr) {
        printk(KERN_ERR "packet_ptr is NULL\n");
        return -EINVAL;
    }
    if (!kfifo_is_full(stack)) {
        kfifo_in(stack, packet_ptr, 1);
    } else {
        printk(KERN_ERR "stack overflow in returning memory back to stack\n");
        return -ENOMEM;
    }

    return 1;
}

unsigned int traffic_netdev_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct ethhdr* eth_h = eth_hdr(skb);
    struct iphdr *ip_h = ip_hdr(skb);  

    if(!eth_h || !ip_h) {
        printk(KERN_INFO "failed to capture ethernet or ip header in traffic_logger module\n");
        return NF_ACCEPT;
    }

    uint32_t proto_hs = ntohs(eth->h_proto);
    if(!whitelist_proto[proto_hs]) {
        return NF_ACCEPT;//skipping uninterested packet O(1)
    }

    int cpu = smp_processor_id();
    atomic_t *local_bcounter = &per_cpu(batch_counter, cpu);
    struct kfifo *local_stack = &per_cpu(packet_mem_stack, cpu);
    struct packet_info *p_info = (struct packet_info *)get_packet_memory(local_stack);

    if(!p_info) {
        printk(KERN_ERR "[BUF_FULL] failed to allocate memory for incoming packet, skipping\n");
        return NF_ACCEPT;
    }
    memcpy(&p_info->eth_h, eth_h, sizeof(struct ethhdr));
    memcpy(&p_info->ip_h, ip_h, sizeof(struct iphdr));

    atomic_inc(local_bcounter);
    int counter = atomic_read(local_bcounter);
    if(counter == BATCH_SIZE) {
        atomic_set(local_bcounter, 0);
        //start workqueue
    }

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
    if (init_packet_cache() < 0) {
        return -EINVAL;
    }
    if (init_packet_memory() < 0) {
        return -EINVAL;
    }
    if(!rhashtable_init(&my_objects, &object_params)) {
        printk(KERN_ERR "Error initing hashtable in logger_init\n");
        return -EINVAL;
    }
    init_hook(&nf_netdev_hook, traffic_netdev_hook, NFPROTO_NETDEV, NF_NETDEV_INGRESS, NF_IP_PRI_FIRST);

    printk(KERN_INFO "Traffic logger module loaded.\n");

    return 0;
}

static void __exit logger_exit(void) {
    int cpu;

    for_each_possible_cpu(cpu) {
        struct kfifo *stack = &per_cpu(packet_mem_stack, cpu);
        kfifo_free(stack);
    }
    cleanup_packet_cache();
    printk(KERN_INFO "Traffic logger module UNloaded.\n");
}

module_init(logger_init);
module_exit(logger_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Den/M22");
MODULE_DESCRIPTION("Packet logger");