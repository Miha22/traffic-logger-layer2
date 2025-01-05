#define CONFIG_NETFILTER
#ifdef CONFIG_NETFILTER

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

#include <linux/slab.h>
#include <linux/workqueue.h>  
#include <linux/kfifo.h>
#include <linux/percpu.h>

#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/wait.h>

#include <buffer.h>
#include <traffic_logger.h>

#define WHITELIST_SIZE 65536

static struct rhashtable rhash_frames;
static struct mac_list *mac_list;//mac strings to dump
DECLARE_WORK(rhash_worker, wq_process_dump);
static DEFINE_PER_CPU(struct kmem_cache *, packet_cache);
static struct nf_hook_ops nfho;
static DEFINE_RWLOCK(rhash_rwlock);
static DECLARE_WAIT_QUEUE_HEAD(writers_wq);
static atomic_t reader_waiting = ATOMIC_INIT(0);//prioritized reader for periodic dumping
static DEFINE_PER_CPU(struct ring_buffer, percpu_circ_buf);
static DEFINE_PER_CPU(atomic_t, batch_counter);
//static DEFINE_PER_CPU(atomic_t, buffer_offset);
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

static struct packet_info *allocate_packet_cache(struct kmem_cache *cachep) {
    return kmem_cache_alloc(cachep, GFP_ATOMIC);
}

static void free_packet_cache(struct kmem_cache *cachep, struct packet_info *pkt) {
    kmem_cache_free(cachep, pkt);
}

static void destroy_packet_cache(struct kmem_cache *cachep) {
    kmem_cache_destroy(cachep);
}

static int init_packet_cache(struct kmem_cache **cache) {
    *cache = kmem_cache_create(
		"packet_cache",
		sizeof(struct packet_info), 
		0, 
		SLAB_HWCACHE_ALIGN, 
		NULL
	);

    if (!*cache) {
        printk(KERN_ERR "Failed to create slab cache for struct packet_info\n");
        return -ENOMEM;
    }

    return 0;
}

static int enqueue_circ_buf(struct ring_buffer *rb, void *data) {
    uint32_t next_tail = (rb->tail + 1 % BUF_SIZE);
    // if(next_tail == rb->head) {
    //     printk(KERN_WARNING "[tail]ring buffer is full, cannot enqueue data\n");
    //     return -1;
    // }
    rb->buffer[rb->tail] = data;
    rb->tail = next_tail;

    return 0;
}

static void* dequeue_circ_buf(struct ring_buffer *rb) {
    // if(rb->head == rb->tail) {
    //     printk(KERN_WARNING "[head]ring buffer is empty, cannot dequeue data\n");
    //     return NULL;
    // }
    void* data = rb->buffer[rb->head];
    uint32_t next_head = (rb->head + 1 % BUF_SIZE);
    rb->head = next_head;

    return data;
}

static int wq_process_dump(struct work_struct *work) { 
    char mac_str[MAC_SIZE];
    //mutex lock
    for(uint32_t = i; i < mac_list->len; i++) {
        snprintf(mac_str, MAC_SIZE, "%pM", mac_list->arr[i]);
        //assemble and dump or dump in stream
    }

    return 0;
}

void dump_htable(void) {
    struct rhashtable_iter iter;
    struct mac_info* obj = NULL;

    atomic_inc(&reader_waiting);
    read_lock(&rhash_rwlock);
    
    rhashtable_walk_enter(&rhash_frames, &iter);
    rhashtable_walk_start(&iter);
    uint32_t i = 0;
    while (i < BUF_SIZE && (obj = (struct mac_info*)rhashtable_walk_next(&iter)) != NULL) {
        if (IS_ERR(obj)) {
            printk(KERN_ERR "Error encountered while iterating hash table\n");
            continue;
        }
            
        memcpy(mac_list->arr[i], obj->src_mac, ETH_ALEN);
        i++;
        if(rhashtable_remove_fast(rhash_frames, &obj->linkage, object_params) == 0)
            kfree(obj);
        else {
            printk(KERN_WARNING "Cannot remove object from rhashtable");
        }
    }
    mac_list->len = i;

    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

    bool res = schedule_work(&rhash_worker);

    read_unlock(&rhash_rwlock);
    atomic_dec(&reader_waiting);
    wake_up_all(&writers_wq);
}

static int wq_process_batch(struct work_struct *work_ptr) {//deferred
    struct work_info *w_info = container_of(work_ptr, struct work_info, work);
    //int cpu = w_info->cpu_id, res = 0;

    struct ring_buffer *rb = &this_cpu_ptr(percpu_circ_buf);
    struct kfifo *w_stack = &this_cpu_ptr(worker_stack);
    spinlock_t *s_lock = &this_cpu_ptr(kfifo_slock);
    atomic_t *b_counter = &this_cpu_ptr(batch_counter);
    int start_index = w_info->batch_start;

    for(int i = start_index; i < BATCH_SIZE + start_index; i++) {
        struct packet_info *p_info = (struct packet_info *)rb->buffer[i];
        const void *key = p_info->eth_h.h_source;
        struct mac_info *found = (struct mac_info *)rhashtable_lookup_fast(&rhash_frames, key, object_params);

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
    if (!kfifo_put(w_stack, w_info)) {
        printk(KERN_ERR "Failed to return worker to stack for CPU %d\n", cpu);
        return -ENOMEM;
    }
    spin_unlock(s_lock);

    return res;
}

static int init_per_cpu(void) {
    int cpu, res;
    for_each_possible_cpu(cpu) {
        struct kmem_cache **cache = &per_cpu(packet_cache, cpu);
        int res = init_packet_cache(cache);

        if(res < 0) {
            return -ENVAL;
        }

        struct ring_buffer *rb = &per_cpu(percpu_circ_buf, cpu);
        for(uint16_t i = 0; i < BUF_SIZE; i++) {
            struct packet_info *p_info = allocate_packet_cache(*cache);
            res = enqueue_circ_buf(rb, p_info);
            if(res < 0) {
                printk(KERN_ERR "Cannot allocate cache for packet during init due to ring buffer error\n");
                return -1;
            }
        }

        atomic_t *b_counter = &per_cpu(batch_counter, cpu);
        atomic_set(b_counter, 0);

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
            local_workers[i].batch_start = i * BATCH_SIZE;
            //local_workers[i].batch_end = local_workers[i].batch_start + BATCH_SIZE;
            INIT_WORK(&local_workers[i].work, wq_process_batch);
            if (!kfifo_put(w_stack, &local_workers[i])) {
                printk(KERN_WARNING "KFIFO full, failed to enqueue worker\n");
                return -ENOMEM;
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

    //int cpu = smp_processor_id();
    struct workqueue_struct *wq_ptr = this_cpu_ptr(percpu_workqueue);
    // struct work_info *local_workers = per_cpu(wq_workers, cpu);
    struct kfifo *w_stack = &this_cpu_ptr(worker_stack);
    spinlock_t *s_lock = &this_cpu_ptr(kfifo_slock);
    atomic_t *b_counter = &this_cpu_ptr(batch_counter);
    //atomic_t *b_offset = &this_cpu_ptr(buffer_offset);
    struct ring_buffer *rb = &this_cpu_ptr(percpu_circ_buf);

    struct packet_info *p_info = (struct packet_info *)dequeue_circ_buf(rb);//taking allocated memory and moving head
    // if(!p_info) {
    //     printk(KERN_WARNING "[BUF_FULL] failed to store incoming packet, skipping\n");
    //     return NF_ACCEPT;
    // }
    memcpy(&p_info->eth_h, eth_h, sizeof(struct ethhdr));
    //memcpy(&p_info->ip_h, ip_h, sizeof(struct iphdr));

    atomic_inc(b_counter);
    counter = atomic_read(b_counter);
    if(counter % BATCH_SIZE == 0) {
        if(counter == BUF_SIZE)
            atomic_set(b_counter, 0);
            
        struct work_info *worker = NULL;
        struct work_info worker_next = NULL;
        if (!kfifo_is_empty(w_stack)) {
            spin_lock(s_lock);
            if (!kfifo_get(w_stack, worker)) {
                //printk(KERN_WARNING "KFIFO empty, failed to dequeue worker\n");
            
            }
            if(!kfifo_peek(w_stack, worker_next)) {
                //printk(KERN_WARNING "KFIFO getting empty, will be no more free space in ring buffer\n");
                
            }
            else {
                //atomic_set(b_offset, worker_next->batch_start);
                rb->head = worker_next->batch_start;
            }
            spin_unlock(s_lock);

            bool res = queue_work(wq_ptr, &worker->work);
            if (!res) {
                printk(KERN_WARNING "Failed to queue work in workqueue\n");
            }
        } else {
            printk(KERN_WARNING "No free workers available. Consider increasing ring buffer size and batch size\n");
            //bandwidth reached
            return NF_ACCEPT;
        }
    }

    return NF_ACCEPT;
}

static void init_hook(struct nf_hook_ops *nfho, 
                    unsigned int (*hook_cb)(void*, struct sk_buff*, const struct nf_hook_state *), 
                    uint8_t protocol, 
                    uint32_t routing, 
                    int32_t priority
                ) {
    nfho->hook = (nf_hookfn*)hook_cb;
    nfho->dev = NULL;
    nfho->pf = protocol;
    nfho->hooknum = routing;
    nfho->priority = priority;
}

static void clear_slab_caches(void) {
    int cpu;
    for_each_possible_cpu(cpu) { 
        struct kmem_cache **cache = &per_cpu(packet_cache, cpu);
        struct ring_buffer *rb = &per_cpu(percpu_circ_buf, cpu);
        struct packet_info *data = NULL;
        for(int i = 0; i < BUF_SIZE; i++) {
            data = (struct packet_info *)rb->buffer[i];
            free_packet_cache(*cache, data);
        }
        destroy_packet_cache(*cache);
    }
}

static void clear_workqueues(void) {
    //flush_scheduled_work();
    cancel_work_sync(&rhash_worker);
    int cpu;
    for_each_possible_cpu(cpu) { 
        struct work_info *local_workers = per_cpu(wq_workers, cpu);
        for(uint16_t i = 0; i < WORKERS_SIZE; i++) {
            cancel_work_sync(&local_workers[i].work);
        }
        
        destroy_workqueue(per_cpu(percpu_workqueue, cpu));
    }
}

static void free_kfifos(void) {
    int cpu;
    for_each_possible_cpu(cpu) {
        struct kfifo *w_stack = &per_cpu(worker_stack, cpu);
        if(!kfifo_is_empty(w_stack)) {

        }
        kfifo_free(w_stack);
    }
}

static int __init logger_init(void) {
    nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if(!nfho) {
        printk(KERN_ERR "Failed to allocate memory for mac list[%d]\n", i);
        return -ENOMEM; 
    }
    mac_list = (struct mac_list *)kmalloc(sizeof(struct mac_list), GFP_KERNEL);
    if(!mac_list) {
        kfree(nfho);
        printk(KERN_ERR "Failed to allocate memory for mac list[%d]\n", i);
        return -ENOMEM; 
    }
    for (int i = 0; i < BUF_SIZE; i++) {
        mac_list->arr[i] = kmalloc(ETH_ALEN, GFP_KERNEL);
        if (mac_list->arr[i] == NULL) {
            printk(KERN_ERR "Failed to allocate memory for mac_list->arr[%d]\n", i);
            for (int j = 0; j < i; j++) {
                kfree(mac_list->arr[j]);
            }
            kfree(mac_list);
            kfree(nfho);
            return -ENOMEM; 
        }
    }
    if (init_per_cpu() < 0) {
        free_kfifos();
        clear_workqueues();
        clear_slab_caches();
        for (int j = 0; j < BUF_SIZE; j++) {
            kfree(mac_list->arr[j]);
        }
        kfree(mac_list);
        kfree(nfho);
        return -EINVAL;
    }
    if(!rhashtable_init(&rhash_frames, &object_params)) {
        free_kfifos();
        clear_workqueues();
        clear_slab_caches();
        for (int j = 0; j < BUF_SIZE; j++) {
            kfree(mac_list->arr[j]);
        }
        kfree(mac_list);
        kfree(nfho);
        printk(KERN_ERR "Error initing hashtable in logger_init\n");
        return -EINVAL;
    }
    init_hook(nfho, traffic_netdev_hook, NFPROTO_NETDEV, NF_NETDEV_INGRESS, NF_IP_PRI_FIRST);
    int ret = nf_register_net_hook(&init_net, nfho); 
    if (ret < 0) {
        free_kfifos();
        clear_workqueues();
        clear_slab_caches();
        for (int j = 0; j < BUF_SIZE; j++) {
            kfree(mac_list->arr[j]);
        }
        kfree(mac_list);
        kfree(nfho);
        printk(KERN_ERR "Failed to register hook: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "Traffic logger module loaded.\n");

    return 0;
}

static void __exit logger_exit(void) {
    nf_unregister_net_hook(&init_net, nfho);
    free_kfifos();
    clear_workqueues();
    clear_slab_caches();

    struct rhashtable_iter iter;
    struct mac_info* obj = NULL;
    atomic_inc(&reader_waiting);
    read_lock(&rhash_rwlock);
    rhashtable_walk_enter(&rhash_frames, &iter);
    rhashtable_walk_start(&iter);

    while ((obj = (struct mac_info*)rhashtable_walk_next(&iter)) != NULL) {
        if (IS_ERR(obj)) {
            printk(KERN_ERR "Error encountered while iterating hash table in log exit\n");
            continue;
        }
        if(rhashtable_remove_fast(rhash_frames, &obj->linkage, object_params) == 0)
            kfree(obj);
        else {
            printk(KERN_WARNING "Cannot remove object from rhashtable");
        }
    }

    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

    read_unlock(&rhash_rwlock);
    atomic_dec(&reader_waiting);

    for (int i = 0; i < BUF_SIZE; i++) {
        kfree(mac_list->arr[i]);
    }
    kfree(mac_list);
    kfree(nfho);
    printk(KERN_INFO "Traffic logger module Unloaded.\n");
}

module_init(logger_init);
module_exit(logger_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Den/M22");
MODULE_DESCRIPTION("Packet logger");

#endif