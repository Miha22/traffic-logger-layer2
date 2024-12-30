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

#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/wait.h>

#include <linux/buffer.h>s
#include <traffic_logger.h>

#define WHITELIST_SIZE 65536
#define BATCH_SIZE 100

static struct rhashtable frames_info;
static struct kmem_cache *packet_cache;
static struct nf_hook_ops nf_netdev_hook;
static DECLARE_RWSEM(htable_semaphore);
static DEFINE_PER_CPU(struct ring_buffer, percpu_circ_buf);
static DEFINE_PER_CPU(atomic_t, batch_counter);
static DECLARE_PER_CPU(struct workqueue_struct *, percpu_workqueue);
static DECLARE_PER_CPU(struct work_info[BUF_SIZE / BATCH_SIZE], wq_workers);
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

struct packet_info *allocate_packet_cache(void) {
    return kmem_cache_alloc(packet_cache, GFP_ATOMIC);
}

void free_packet_cache(struct packet_info *pkt) {
    kmem_cache_free(packet_cache, pkt);
}

void destroy_packet_cache(void) {
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

int enqueue_circ_buf(struct ring_buffer *rb, void *data) {
    uint32_t next_tail = (rb->tail + 1 % BUF_SIZE);
    if(next_tail == rb->head) {
        printk(KERN_WARNING "[tail]ring buffer is full, cannot enqueue data\n");
        return -1;
    }
    rb->buffer[rb->tail] = data;
    rb->tail = next_tail;

    return 1;
}

void* dequeue_circ_buf(struct ring_buffer *rb) {
    if(rb->head == rb->tail) {
        printk(KERN_WARNING "[head]ring buffer is empty, cannot denqueue data\n");
        return NULL;
    }
    void* data = rb->buffer[rb->head];
    uint32_t next_head = (rb->head + 1 % BUF_SIZE);
    rb->head = next_head;

    return data;
}

int wq_process_batch(struct work_struct *work) {
    struct work_info *w_info = container_of(work, struct work_info, work);
    int cpu_id = w_info->cpu_id;

    struct ring_buffer *rb = &per_cpu(percpu_circ_buf, cpu_id);

    for(uint16_t i = 0; i < BUF_SIZE; i++) {
        struct packet_info *p_info = dequeue_circ_buf(rb);//return packet_info back to ring buffer that was just read now
        unsigned char source_mac[ETH_ALEN];
        memcpy(source_mac, p_info->eth_h.h_source, ETH_ALEN);
        uint32_t hash = jhash(source_mac, ETH_ALEN, 0);
    }
}

int init_per_cpu(void) {
    if(packet_cache == NULL) {
        printk(KERN_ERR "Cache must be initialized first\n");
        return -EPERM;
    }
    int cpu, ret;
    for_each_possible_cpu(cpu) {
        struct workqueue_struct *wq = alloc_workqueue("percpu_wq_%d", WQ_UNBOUND, 0, cpu);
        if (!wq) {
            printk(KERN_ERR "Failed to allocate workqueue for CPU %d\n", cpu);
            return -ENOMEM;
        }
        struct workqueue_struct **wq_ptr = &per_cpu(percpu_workqueue, cpu);
        *wq_ptr = wq;

        struct work_info *local_workers = per_cpu(wq_workers, cpu);
        for (int i = 0; i < BUF_SIZE / BATCH_SIZE; i++) {
            local_workers[i].cpu_id = cpu;
            INIT_WORK(&local_workers[i].work, wq_process_batch);
        }

        atomic_t *b_counter = &per_cpu(batch_counter, cpu);
        *b_counter = ATOMIC_INIT(0);

        spinlock_t *s_lock = &per_cpu(stack_lock, cpu);
        spin_lock_init(s_lock);

        struct ring_buffer *rb = &per_cpu(percpu_circ_buf, cpu);
        for(uint16_t i = 0; i < BUF_SIZE; i++) {
            struct packet_info *p_info = allocate_packet_cache();
            int res = enqueue_circ_buf(rb, p_info);
            if(res < 0) {
                printk(KERN_ERR "Cannot allocate cache for packet during init due to ring buffer error\n");
                return -1;
            }
        }
    }

    return 1;
}

//[REPLACED with dequeue_circ_buf()]
// struct packet_info *get_packet_memory(struct ring_buffer *rb) {
//     struct packet_info *p_info = (struct packet_info *)dequeue_circ_buf(rb);

//     if (p_info == NULL) {
//         printk(KERN_WARNING "[BUF_EMPTY_NOT_ALLOCATED] Failed to place incoming packet into memory\n");
//         return NULL;
//     }

//     return p_info;
// }
//[REPLACED with enqueue_circ_buf()]
// int return_packet_memory(struct ring_buffer *rb, void* p_info) {
//     if (!packet_ptr) {
//         printk(KERN_ERR "packet_ptr is NULL\n");
//         return -EINVAL;
//     }
//     int res = enqueue_circ_buf(rb, p_info);
//     if (res < 0) {
//         printk(KERN_ERR "stack overflow in returning memory back to stack\n");
//         return -ENOMEM;
//     }

//     return 1;
// }

unsigned int traffic_netdev_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct ethhdr* eth_h = eth_hdr(skb);
    struct iphdr *ip_h = ip_hdr(skb);  

    if(!eth_h || !ip_h) {
        printk(KERN_INFO "failed to capture ethernet or ip header in traffic_logger module\n");
        return NF_ACCEPT;
    }

    uint32_t proto_hs = ntohs(eth->h_proto);
    if(!whitelist_proto[proto_hs]) {
        return NF_ACCEPT;
    }

    int cpu = smp_processor_id();
    struct workqueue_struct *wq_ptr = per_cpu(percpu_workqueue, cpu);
    struct work_info *local_workers = per_cpu(wq_workers, cpu);
    atomic_t *packet_counter = &per_cpu(batch_counter, cpu);
    struct ring_buffer *rb = &per_cpu(percpu_circ_buf, cpu);

    int counter = atomic_read(packet_counter);
    if(counter == 0) {
        rb->head_initial = rb->head;
    }

    //assembling batch
    struct packet_info *p_info = (struct packet_info *)dequeue_circ_buf(rb);
    if(!p_info) {
        printk(KERN_WARNING "[BUF_FULL] failed to store incoming packet, skipping\n");
        return NF_ACCEPT;
    }
    memcpy(&p_info->eth_h, eth_h, sizeof(struct ethhdr));
    memcpy(&p_info->ip_h, ip_h, sizeof(struct iphdr));

    atomic_inc(packet_counter);
    counter = atomic_read(packet_counter);
    if(counter == BATCH_SIZE) {
        rb->head = rb->head_initial;//for workqueue to work correctly from the beginning of filled packet_info (-s)
        atomic_set(packet_counter, 0);
        //allocate for any next free worker, will use kfifo stack for that.
        queue_work(wq_ptr, &local_workers[0].work);//test
    }

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
    if (init_packet_cache() < 0) {
        return -EINVAL;
    }
    if (init_per_cpu() < 0) {
        destroy_packet_cache();
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
        struct workqueue_struct wq_ptr* = per_cpu(percpu_workqueue, cpu);
        struct kfifo *stack = &per_cpu(packet_mem_stack, cpu);
        for(uint16_t i = 0; i < BUF_SIZE; i++) {
            struct packet_info *p_info = NULL;
            if (!kfifo_is_empty(stack)) {
                kfifo_out(stack, &p_info, 1);
                free_packet_cache(p_info);
            }
        }
        kfifo_free(stack); 
    }
    destroy_packet_cache();
    printk(KERN_INFO "Traffic logger module UNloaded.\n");
}

module_init(logger_init);
module_exit(logger_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Den/M22");
MODULE_DESCRIPTION("Packet logger");