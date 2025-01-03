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

#include <buffer.h>s
#include <traffic_logger.h>

#define WHITELIST_SIZE 65536

static struct rhashtable rhash_frames;
static struct rhashtable rhash_frames_copy;
DECLARE_WORK(rhash_worker, wq_process_dump);
static struct kmem_cache *packet_cache;
static struct nf_hook_ops nf_netdev_hook;
static DEFINE_RWLOCK(rhash_rwlock);
static DECLARE_WAIT_QUEUE_HEAD(writers_wq);
static atomic_t reader_waiting = ATOMIC_INIT(0);//prioritized reader for periodic dumping
static DEFINE_PER_CPU(struct ring_buffer, percpu_circ_buf);
static DEFINE_PER_CPU(atomic_t, batch_counter);
static DECLARE_PER_CPU(struct workqueue_struct *, percpu_workqueue);
static DECLARE_PER_CPU(struct work_info[WORKERS_SIZE], wq_workers);
static DEFINE_PER_CPU(struct kfifo, worker_stack);
static DEFINE_PER_CPU(spinlock_t, kfifo_slock);

static int32_t whitelist_proto[WHITELIST_SIZE] = {
    [ETH_P_IP] = 1,
    [ETH_P_IPV6] = 1,
    [ETH_P_ARP] = 1,
    [ETH_P_RARP] = 1,
    [ETH_P_MPLS_UC] = 1,
    [ETH_P_BATMAN] = 1,
    [ETH_P_LLDP] = 1,
};

static u32 mac_hashfn(const void *data, u32 len, u32 seed)
{
    return jhash(data, len, seed);
}

static int mac_obj_cmpfn(struct rhashtable_compare_arg *arg, const void *obj)
{
    const unsigned char *key = arg->key;
    const struct mac_info *mi = obj;

    return memcmp(key, mi->src_mac, ETH_ALEN);
}

const static struct rhashtable_params object_params = {
	.key_len     = ETH_ALEN,
	.key_offset  = offsetof(struct mac_info, key),
	.head_offset = offsetof(struct mac_info, linkage),
    .hashfn      = mac_hashfn,
    .obj_cmpfn   = mac_obj_cmpfn,
};

static struct packet_info *allocate_packet_cache(void) {
    return kmem_cache_alloc(packet_cache, GFP_ATOMIC);
}

static void free_packet_cache(struct packet_info *pkt) {
    kmem_cache_free(packet_cache, pkt);
}

static void destroy_packet_cache(void) {
    kmem_cache_destroy(packet_cache);
}

static int init_packet_cache(void) {
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

    return 0;
}

static int enqueue_circ_buf(struct ring_buffer *rb, void *data) {
    uint32_t next_tail = (rb->tail + 1 % BUF_SIZE);
    if(next_tail == rb->head) {
        printk(KERN_WARNING "[tail]ring buffer is full, cannot enqueue data\n");
        return -1;
    }
    rb->buffer[rb->tail] = data;
    rb->tail = next_tail;

    return 0;
}

static void* dequeue_circ_buf(struct ring_buffer *rb) {
    if(rb->head == rb->tail) {
        printk(KERN_WARNING "[head]ring buffer is empty, cannot dequeue data\n");
        return NULL;
    }
    void* data = rb->buffer[rb->head];
    uint32_t next_head = (rb->head + 1 % BUF_SIZE);
    rb->head = next_head;

    return data;
}

static int wq_process_dump(struct work_struct *work) { 


    return 0;
}

void dump_htable(void) {
    struct rhashtable_iter iter;
    struct mac_info* obj = NULL;

    atomic_inc(&reader_waiting);
    read_lock(&rhash_rwlock);
    
    rhashtable_walk_enter(&frames_info, &iter);
    rhashtable_walk_start(&iter);

    while ((obj = (struct mac_info*)rhashtable_walk_next(&iter)) != NULL) {
        if (IS_ERR(obj))
            continue;

        struct mac_info *new_obj = kmalloc(sizeof(struct mac_info), GFP_ATOMIC);
        if (!new_obj) {
            printk(KERN_ERR "Failed to allocate memory for snapshot\n");
            break;
        }

        memcpy(new_obj, obj, sizeof(struct mac_info));
        rhashtable_insert_fast(&rhash_frames_copy, &new_obj->linkage, object_params);
    }

    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

    bool res = schedule_work(&rhash_worker);

    read_unlock(&rhash_rwlock);
    atomic_dec(&reader_waiting);
    wake_up_all(&writers_wq);
}

static int wq_process_batch(struct work_struct *work) {
    struct work_info *w_info = container_of(work, struct work_info, work);
    int cpu_id = w_info->cpu_id, res = 0;

    struct ring_buffer *rb = &per_cpu(percpu_circ_buf, cpu_id);
    struct kfifo *w_stack = &per_cpu(worker_stack, cpu);
    spinlock_t *s_lock = &per_cpu(kfifo_slock, cpu);
    atomic_t *b_counter = &per_cpu(batch_counter, cpu);
    int counter = atomic_read(b_counter);
    uint32_t start_index = (rb->tail + 1) % BUF_SIZE;

    for(uint16_t i = start_index; i < BATCH_SIZE + start_index; i++) {
        struct packet_info *p_info = &((struct packet_info *)rb->buffer)[i % BUF_SIZE];
        const void *key = p_info->eth_h.h_source;
        struct mac_info *found = (struct mac_info *)rhashtable_lookup_fast(&frames_info, key, object_params);

        if (found) {
            int res = enqueue_circ_buf(rb, p_info);//batch tail needed
            if (res < 0) {
                printk(KERN_WARNING "ring buffer overflow on CPU %d\n", cpu_id);
            }     
            continue;
        }

        struct mac_info *mi = kmalloc(sizeof(struct mac_info), GFP_ATOMIC);
        if(!mi) {
            printk(KERN_ERR "Failed to allocate memory in batch processor\n");
            return -ENOMEM;
        }
        mi->counter = 1;
        memcpy(mi->src_mac, p_info->eth_h.h_source, ETH_ALEN);

        while (atomic_read(&reader_waiting) > 0) {//dumping taking place
            wait_event(writers_wq, atomic_read(&reader_pending) == 0);
        }

        write_lock(&rhash_rwlock);
        struct mac_info * old_obj = (struct mac_info *)rhashtable_lookup_get_insert_fast(&rhash_frames, &mi->linkage, object_params);
        write_unlock(&rhash_rwlock);
        
        if(IS_ERR(old_obj)) {
            kfree(mi); 
            printk(KERN_ERR "Failed to insert object into hash table in batch processor\n");
            res = PTR_ERR(old_obj);
        }
        // else if(old_obj) {//exists
        //     kfree(mi); 
        //     old_obj->counter++;
        // }
        //else inserted and NULL returned
        int res = enqueue_circ_buf(rb, p_info);//rb->tail at the end will be equal (start_index + BATCH_SIZE - 2) t
        //return memory back for new write (so dequeue uses it)
        if (res < 0) {
            printk(KERN_WARNING "ring buffer overflow on CPU %d\n", cpu_id);
        }      
    }
    spin_lock(s_lock);
    if (!kfifo_in(w_stack, work, sizeof(struct work_info *))) {//returning work back to stack kfifo
        printk(KERN_ERR "Failed to return worker to stack for CPU %d\n", cpu);
        return -ENOMEM;
    }
    spin_unlock(s_lock);

    return res;
}

static int init_per_cpu(void) {
    if(packet_cache == NULL) {
        printk(KERN_ERR "Cache must be initialized first\n");
        return -EPERM;
    }
    int cpu, res;
    for_each_possible_cpu(cpu) {
        char wq_name[32];
        snprintf(wq_name, sizeof(wq_name), "percpu_wq_%d", cpu);
        struct workqueue_struct *wq = alloc_workqueue(wq_name, WQ_UNBOUND, 0);
        if (!wq) {
            printk(KERN_ERR "Failed to allocate workqueue for CPU %d\n", cpu);
            return -ENOMEM;
        }

        struct workqueue_struct **wq_ptr = &per_cpu(percpu_workqueue, cpu);
        *wq_ptr = wq;

        struct kfifo *w_stack = &per_cpu(worker_stack, cpu);
        res = kfifo_alloc(w_stack, WORKERS_SIZE * sizeof(struct work_info *), GFP_KERNEL);
        if (res) {
            printk(KERN_ERR "Failed to allocate kfifo for CPU %d\n", cpu);
            return -1;
        }

        spinlock_t *s_lock = &per_cpu(kfifo_slock, cpu);
        spin_lock_init(s_lock);

        struct work_info *local_workers = per_cpu(wq_workers, cpu);
        for (int i = 0; i < WORKERS_SIZE; i++) {
            local_workers[i].cpu_id = cpu;
            INIT_WORK(&local_workers[i].work, wq_process_batch);

            if (!kfifo_in(w_stack, &local_workers[i], sizeof(struct work_info *))) {
                printk(KERN_ERR "Failed to initialize worker stack for CPU %d\n", cpu);
                kfifo_free(w_stack);
                return -ENOMEM;
            }
        }

        atomic_t *b_counter = &per_cpu(batch_counter, cpu);
        atomic_set(b_counter, 0);

        struct ring_buffer *rb = &per_cpu(percpu_circ_buf, cpu);
        for(uint16_t i = 0; i < BUF_SIZE; i++) {
            struct packet_info *p_info = allocate_packet_cache();
            res = enqueue_circ_buf(rb, p_info);
            if(res < 0) {
                printk(KERN_ERR "Cannot allocate cache for packet during init due to ring buffer error\n");
                return -1;
            }
        }
    }

    return 0;
}

static unsigned int traffic_netdev_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
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
    // struct work_info *local_workers = per_cpu(wq_workers, cpu);
    struct kfifo *w_stack = &per_cpu(worker_stack, cpu);
    spinlock_t *s_lock = &per_cpu(kfifo_slock, cpu);
    atomic_t *b_counter = &per_cpu(batch_counter, cpu);
    struct ring_buffer *rb = &per_cpu(percpu_circ_buf, cpu);

    struct packet_info *p_info = (struct packet_info *)dequeue_circ_buf(rb);//taking allocated memory and moving head
    if(!p_info) {
        printk(KERN_WARNING "[BUF_FULL] failed to store incoming packet, skipping\n");
        return NF_ACCEPT;
    }
    memcpy(&p_info->eth_h, eth_h, sizeof(struct ethhdr));
    //memcpy(&p_info->ip_h, ip_h, sizeof(struct iphdr));

    atomic_inc(b_counter);
    counter = atomic_read(b_counter);
    if(counter % BATCH_SIZE == 0) {
        struct work_info *worker = NULL;

        if (!kfifo_is_empty(w_stack)) {
            spin_lock(s_lock);
            kfifo_out(w_stack, &worker, sizeof(struct work_info *));
            spin_unlock(s_lock);
            bool res = queue_work(wq_ptr, &worker->work);
        } else {
            printk(KERN_WARNING "No free workers available\n");
            //
            return NF_ACCEPT;
        }

        queue_work(wq_ptr, &worker.work);
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
    if(!rhashtable_init(&rhash_frames, &object_params)) {
        printk(KERN_ERR "Error initing hashtable in logger_init\n");
        return -EINVAL;
    }
    if(!rhashtable_init(&rhash_frames_copy, &object_params)) {
        printk(KERN_ERR "Error initing hashtable #2 in logger_init\n");
        return -EINVAL;
    }
    init_hook(&nf_netdev_hook, traffic_netdev_hook, NFPROTO_NETDEV, NF_NETDEV_INGRESS, NF_IP_PRI_FIRST);

    printk(KERN_INFO "Traffic logger module loaded.\n");

    return 0;
}

static void __exit logger_exit(void) {
    int cpu;
    for_each_possible_cpu(cpu) {
        struct ring_buffer *rb = &per_cpu(percpu_circ_buf, cpu);
        struct packet_info *data = NULL;
        while ((data = dequeue_circ_buf(rb)) != NULL) {
            free_packet_cache(data);
        }
        destroy_workqueue(per_cpu(percpu_workqueue, cpu));
    }
    destroy_packet_cache();
    printk(KERN_INFO "Traffic logger module UNloaded.\n");
}

module_init(logger_init);
module_exit(logger_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Den/M22");
MODULE_DESCRIPTION("Packet logger");