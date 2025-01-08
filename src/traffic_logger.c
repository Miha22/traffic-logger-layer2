#define CONFIG_NETFILTER
#ifdef CONFIG_NETFILTER

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/workqueue.h>  
#include <linux/kfifo.h>
#include <linux/rhashtable.h>

#include <linux/rcupdate.h>
#include <linux/rwlock.h>
#include <linux/spinlock.h>

#include <buffer.h>
#include <file_logger.h>
#include <traffic_logger.h>

static struct rhashtable rhash_frames;
static struct nf_hook_ops *nfho;
static struct mac_list *mac_list;

//DEFINE_PER_CPU(struct kmem_cache *, packet_cache);
static DEFINE_RWLOCK(rhash_rwlock);
DEFINE_PER_CPU(struct ring_buffer *, percpu_circ_buf);
DEFINE_PER_CPU(atomic_t, batch_counter);
DEFINE_PER_CPU(atomic_t, skip_counter);
//DEFINE_PER_CPU(struct workqueue_struct *, percpu_workqueue);
//DEFINE_PER_CPU(struct work_info[WORKERS_SIZE], wq_workers);
DEFINE_PER_CPU(struct kfifo *, worker_stack);
DEFINE_PER_CPU(spinlock_t, kfifo_slock);

static struct proc_dir_entry *proc_file;
static DECLARE_DELAYED_WORK(mac_dump_work, dump_htable);
static char *dump_buffer;
static size_t buffer_len;
static DEFINE_MUTEX(buffer_lock);

static ssize_t proc_read_cb(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    mutex_lock(&buffer_lock);
    ssize_t ret = simple_read_from_buffer(buf, count, ppos, dump_buffer, buffer_len);
    mutex_unlock(&buffer_lock);

    return ret;
}

static const struct proc_ops proc_fops = {
    .proc_read = proc_read_cb,
};

static u32 mac_hashfn(const void *data, u32 len, u32 seed)
{
    const unsigned char *key = (const unsigned char *)data;
    return jhash(key, ETH_ALEN, seed);
}

static int mac_obj_cmpfn(struct rhashtable_compare_arg *arg, const void *obj)
{
    if (!arg || !arg->key || !obj) {
        printk(KERN_ERR "mac_obj_cmpfn: Invalid arguments\n");
        return -EINVAL;
    }

    const unsigned char *key = arg->key;
    const struct mac_info *mi = obj;

    if (memcmp(key, mi->src_mac, ETH_ALEN) == 0)
        return 0;

    return -ESRCH;
}

static const struct rhashtable_params object_params = {
    .key_len     = ETH_ALEN,
    .key_offset  = offsetof(struct mac_info, src_mac),
    .head_offset = offsetof(struct mac_info, linkage),
    .hashfn      = mac_hashfn,
    .obj_cmpfn   = mac_obj_cmpfn,
};

void dump_htable(struct work_struct *work) {
    struct rhashtable_iter iter;
    struct mac_info* obj = NULL;

    rcu_read_lock();
    
    rhashtable_walk_enter(&rhash_frames, &iter);
    rhashtable_walk_start(&iter);
    uint32_t i = 0;
    while (i < BUF_SIZE && (obj = (struct mac_info*)rhashtable_walk_next(&iter)) != NULL) {
        if (IS_ERR(obj)) {
            printk(KERN_ERR "Error encountered while iterating hash table\n");
            continue;
        }
            
        memcpy(mac_list->arr[i], obj->src_mac, ETH_ALEN);
        if(rhashtable_remove_fast(&rhash_frames, &obj->linkage, object_params) == 0)
            kfree_rcu(obj, r_head);
        else {
            printk(KERN_WARNING "Cannot remove object from rhashtable");
        }
        i++;
    }
    mac_list->len = i;

    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);
    rcu_read_unlock();
    synchronize_rcu();

    size_t offset = 0;
    mutex_lock(&buffer_lock);
    memset(dump_buffer, 0, PAGE_SIZE);

    for (int i = 0; i < mac_list->len; i++) {
        if (!mac_list->arr[i]) {
            pr_warn("NULL pointer at mac_list->arr[%d]\n", i);
            continue;
        }

        offset += scnprintf(dump_buffer + offset, PAGE_SIZE - offset,
                            "%02x:%02x:%02x:%02x:%02x:%02x\n",
                            mac_list->arr[i][0], mac_list->arr[i][1], mac_list->arr[i][2],
                            mac_list->arr[i][3], mac_list->arr[i][4], mac_list->arr[i][5]);

        if (offset >= PAGE_SIZE) {
            pr_warn("MAC dump truncated due to buffer size\n");
            break;
        }
    }
    buffer_len = offset;
    mac_list->len = 0;

    mutex_unlock(&buffer_lock);

    printk(KERN_INFO "Periodic MAC dump completed and accounting reset (%zu bytes).\n", buffer_len);
    schedule_delayed_work(&mac_dump_work, msecs_to_jiffies(DUMP_PERIOD));
    // atomic_inc(&reader_waiting);
    // read_lock(&rhash_rwlock);

    // //reset table

    // read_unlock(&rhash_rwlock);
    // atomic_dec(&reader_waiting);
    // wake_up_all(&writers_wq);
}

static int init_delayed_dump(void) {
    proc_file = proc_create("mac_dump", 0, NULL, &proc_fops);
    if (!proc_file) {
        printk(KERN_ERR "Failed to create /proc/mac_dump\n");
        return -ENOMEM;
    }

    schedule_delayed_work(&mac_dump_work, msecs_to_jiffies(DUMP_PERIOD));
    printk(KERN_INFO "mac_dump initialized\n");
    return 0;
}

static int32_t whitelist_proto[WHITELIST_SIZE] = {
    [ETH_P_IP] = 1,
    [ETH_P_IPV6] = 1,
    [ETH_P_ARP] = 1,
    [ETH_P_RARP] = 1,
    [ETH_P_MPLS_UC] = 1,
    [ETH_P_BATMAN] = 1,
    [ETH_P_LLDP] = 1,
};

// static struct packet_info *allocate_packet_cache(struct kmem_cache *cachep) {
//     return kmem_cache_alloc(cachep, GFP_KERNEL);
// }

// static void free_packet_cache(struct kmem_cache *cachep, struct packet_info *pkt) {
//     kmem_cache_free(cachep, pkt);
// }

// static void destroy_packet_cache(struct kmem_cache *cachep) {
//     kmem_cache_destroy(cachep);
// }

// static int init_packet_cache(struct kmem_cache **cache) {
//     *cache = kmem_cache_create(
// 		"packet_cache",
// 		sizeof(struct packet_info), 
// 		0, 
// 		SLAB_HWCACHE_ALIGN, 
// 		NULL
// 	);

//     if (!*cache) {
//         printk(KERN_ERR "Failed to create slab cache for struct packet_info\n");
//         return -ENOMEM;
//     }

//     return 0;
// }

// static int enqueue_circ_buf(struct ring_buffer *rb, void *data) {
//     uint32_t next_tail = (rb->tail + 1) % BUF_SIZE;
//     // if(next_tail == rb->head) {
//     //     printk(KERN_WARNING "[tail]ring buffer is full, cannot enqueue data\n");
//     //     return -1;
//     // }
//     rb->buffer[rb->tail] = data;
//     rb->tail = next_tail;

//     return 0;
// }

static void* dequeue_circ_buf(struct ring_buffer *rb) {
    if(rb->head == -1)//no more space for incoming frame
        return NULL;
    // if(rb->head == rb->tail) {
    //     printk(KERN_WARNING "[head]ring buffer is empty, cannot dequeue data\n");
    //     return NULL;
    // }
    if(!rb->buffer[rb->head]) {
        printk(KERN_WARNING "Dequeued null data from ring buffer\n");
        return NULL;
    }
    void* data = rb->buffer[rb->head];
    int next_head = (rb->head + 1) % BUF_SIZE;
    rb->head = next_head;

    return data;
}

static void wq_process_batch(struct work_struct *work_ptr) {//deferred
    struct work_info *w_info = container_of(work_ptr, struct work_info, work);
    struct ring_buffer **rb_ptr = this_cpu_ptr(&percpu_circ_buf);
    struct ring_buffer *rb = *rb_ptr;

    struct kfifo **w_stack_ptr = this_cpu_ptr(&worker_stack);
    if (!w_stack_ptr || !(*w_stack_ptr)) {
        printk(KERN_ERR "[wq_process_batch] kfifo is NULL\n");
        return;
    }
    struct kfifo *w_stack = *w_stack_ptr;
    spinlock_t *s_lock = this_cpu_ptr(&kfifo_slock);
    uint32_t start_index = w_info->batch_start;

    struct mac_info *mi = kmalloc(sizeof(struct mac_info), GFP_ATOMIC);
    if(!mi) {
        spin_lock(s_lock);
        // if (!kfifo_put(w_stack, w_info)) {
        //     spin_unlock(s_lock);
        //     printk(KERN_ERR "Failed to return worker to stack for CPU %d\n");
        //     //return -ENOMEM;
        // }
        if (kfifo_in(w_stack, &w_info, sizeof(void *)) != sizeof(void *)) {
            printk(KERN_WARNING "KFIFO full, failed to enqueue worker\n");
        }
        
        if(rb->head == -1)
            rb->head = start_index;
        spin_unlock(s_lock);
        printk(KERN_ERR "Failed to allocate memory in batch processor\n");
        //return -ENOMEM;
    }

    for(uint32_t i = start_index; i < BATCH_SIZE + start_index; i++) {
        struct packet_info *p_info = (struct packet_info *)rb->buffer[i];//cannot be NULL, hook checked it
        const void *key = p_info->eth_h.h_source;
        rcu_read_lock();
        struct mac_info *found = (struct mac_info *)rhashtable_lookup_fast(&rhash_frames, key, object_params);
        rcu_read_unlock(); 

        if (found) { //this mac exists - skip
            continue;
        }
        memcpy(mi->src_mac, p_info->eth_h.h_source, ETH_ALEN);

        // while (atomic_read(&reader_waiting) > 0) {//rhashtable being reset
        //     wait_event(writers_wq, atomic_read(&reader_waiting) == 0);
        // }

        write_lock(&rhash_rwlock);
        struct mac_info * old_obj = (struct mac_info *)rhashtable_lookup_get_insert_fast(&rhash_frames, &mi->linkage, object_params);
        write_unlock(&rhash_rwlock);
        
        if(IS_ERR(old_obj)) {
            printk(KERN_ERR "Failed to insert object into hash table in batch processor\n");
            //res = PTR_ERR(old_obj);
        }
        // else if(old_obj) {//exists
        //     kfree(mi); 
        //     old_obj->counter++;
        // }
        //else inserted and NULL returned
        // int res = insert_circ_buf(rb, i, p_info);//rb->tail at the end will be equal (start_index + BATCH_SIZE - 2) t
        // if (res < 0) {
        //     printk(KERN_WARNING "Error returning memory for index %d\n", i);
        // }   
        //return memory back for new write (so dequeue uses it)   
    }
    kfree(mi); 
    spin_lock(s_lock);
    // if (!kfifo_put(w_stack, w_info)) {
    //     spin_unlock(s_lock);
    //     printk(KERN_ERR "Failed to return worker to stack for CPU %d\n");
    //     //return -ENOMEM;
    // }
    if (kfifo_in(w_stack, &w_info, sizeof(void *)) != sizeof(void *)) {
        printk(KERN_WARNING "KFIFO full, failed to enqueue worker\n");
    }
    if(rb->head == -1)
        rb->head = start_index;
    spin_unlock(s_lock);
    atomic_t *s_counter = this_cpu_ptr(&skip_counter);
    //do smth maybe
    atomic_set(s_counter, 0);

    //return 0;
}

static unsigned int traffic_netdev_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct ethhdr* eth_h = eth_hdr(skb);
    //struct iphdr *ip_h = ip_hdr(skb);  

    if(!eth_h) {
        printk(KERN_INFO "failed to capture ethernet or ip header in traffic_logger module\n");
        return NF_ACCEPT;
    }

    int proto_hs = ntohs(eth_h->h_proto);
    if(!whitelist_proto[proto_hs]) {
        return NF_ACCEPT;
    }

    atomic_t *b_counter = this_cpu_ptr(&batch_counter);
    struct ring_buffer **rb_ptr = this_cpu_ptr(&percpu_circ_buf);
    struct ring_buffer *rb = *rb_ptr;

    struct packet_info *p_info = (struct packet_info *)dequeue_circ_buf(rb);
    if(!p_info) {//skip until some worker from workqueue return free in kfifo of available workers
        //printk(KERN_WARNING "[BUF_FULL] no more space for incoming packet, skipping\n");
        atomic_inc(this_cpu_ptr(&skip_counter));
        return NF_ACCEPT;
    }
    memcpy(&p_info->eth_h, eth_h, sizeof(struct ethhdr));

    atomic_inc(b_counter);
    int counter = atomic_read(b_counter);
    if(counter % BATCH_SIZE == 0) {
        atomic_set(b_counter, 0);
        //atomic_cmpxchg(b_counter, BUF_SIZE, 0);
        struct kfifo **w_stack_ptr = this_cpu_ptr(&worker_stack);
        if (!w_stack_ptr || !(*w_stack_ptr)) {
            printk(KERN_ERR "[traffic_netdev_hook] kfifo is NULL:%d\n");
            return NF_ACCEPT;
        }
        struct kfifo *w_stack = *w_stack_ptr;

        spinlock_t *s_lock = this_cpu_ptr(&kfifo_slock);

        spin_lock(s_lock);
        void *worker_ptr;
        if (kfifo_out(w_stack, &worker_ptr, sizeof(void *)) != sizeof(void *)) {
            printk(KERN_WARNING "[traffic_netdev_hook] kfifo is empty, failed to pop worker\n");
            return NF_ACCEPT;
        }
        struct work_info *worker = (struct work_info *)worker_ptr;
        
        void *worker_ptr_next;
        if (kfifo_out_peek(w_stack, &worker_ptr_next, sizeof(void *)) != sizeof(void *)) {
            rb->head = -1; // no more items in the kfifo
        } else {
            struct work_info *worker_next = (struct work_info *)worker_ptr_next;
            rb->head = worker_next->batch_start; // update head for the next batch
        }
        // if (!kfifo_get(w_stack, &worker)) {//bandwidth reached
        //     spin_unlock(s_lock);
        //     printk(KERN_WARNING "No free workers available. Consider increasing ring buffer size and batch size\n");
        //     return NF_ACCEPT;
        // }

        spin_unlock(s_lock);

        //int cpu = smp_processor_id();
        if (!schedule_work_on(worker->cpu_id, &worker->work)) {
            printk(KERN_WARNING "Failed to queue work in workqueue\n");
        }
    }

    return NF_ACCEPT;
}

static int init_per_cpu(void) {
    int cpu;
    for_each_possible_cpu(cpu) {
        //struct kmem_cache **cache = per_cpu_ptr(&packet_cache, cpu);
        int res = 0;

        // if (res < 0) {
        //     printk(KERN_ERR "Failed to initialize packet cache on cpu:%d  err: %d\n", cpu, res);

        //     return res;
        // }

        struct ring_buffer **rb = per_cpu_ptr(&percpu_circ_buf, cpu);
        *rb = (struct ring_buffer *)kmalloc(sizeof(struct ring_buffer), GFP_KERNEL);
        if (!*rb) {
            printk(KERN_ERR "Failed to allocate memory for ring buffer per cpu %d\n", cpu);
            return -ENOMEM;
        }
        (*rb)->head = 0;
        (*rb)->tail = 0;
        for(uint32_t i = 0; i < BUF_SIZE; i++) {
            //struct packet_info *p_info = allocate_packet_cache(*cache);
            struct packet_info *p_info = (struct packet_info *)kmalloc(sizeof(struct packet_info), GFP_KERNEL);
            if(!p_info) {
                printk(KERN_ERR "[kmalloc] Cannot allocate memory for packet during init due to ring buffer error\n");
                return -1;
            }
            //res = enqueue_circ_buf(*rb, p_info);
            (*rb)->buffer[i] = p_info;
            printk(KERN_INFO "[ok] memory for 'ring' buffer[%d] on cpu:%d\n", i, cpu);
            // if(res < 0) {
            //     printk(KERN_ERR "Cannot allocate cache for packet during init due to ring buffer error\n");
            //     return -1;
            // }
        }

        atomic_t *b_counter = per_cpu_ptr(&batch_counter, cpu);
        atomic_set(b_counter, 0);

        //char wq_name[32];
        //snprintf(wq_name, sizeof(wq_name), "percpu_wq_%d", cpu);
        // struct workqueue_struct *wq = alloc_workqueue(wq_name, WQ_UNBOUND, 0);
        // if (!wq) {
        //     printk(KERN_ERR "Failed to allocate workqueue for CPU %d\n", cpu);
        //     return -ENOMEM;
        // }

        // struct workqueue_struct **wq_ptr = per_cpu_ptr(&percpu_workqueue, cpu);
        // *wq_ptr = wq;

        struct kfifo **w_stack = per_cpu_ptr(&worker_stack, cpu);
        *w_stack = (struct kfifo *)kmalloc(sizeof(struct kfifo), GFP_KERNEL); 
        if (!*w_stack) {
            printk(KERN_ERR "[kfifo **w_stack] Failed to allocate memory for kfifo struct\n");
            return -ENOMEM; 
        }
        res = kfifo_alloc(*w_stack, WORKERS_SIZE * sizeof(void *), GFP_KERNEL);
        if (res) {
            kfree(*w_stack);
            printk(KERN_ERR "[kfifo_alloc] Failed to allocate kfifo for CPU %d\n", cpu);
            return -1;
        }

        printk(KERN_INFO "successfully allocated kfifo worker_stack for cpu %d\n", cpu);

        spinlock_t *s_lock = per_cpu_ptr(&kfifo_slock, cpu);
        spin_lock_init(s_lock);

        atomic_t *s_counter = per_cpu_ptr(&skip_counter, cpu);
        atomic_set(s_counter, 0);

        //struct work_info *local_workers = per_cpu_ptr(wq_workers, cpu);
        for (uint32_t i = 0; i < WORKERS_SIZE; i++) {
            struct work_info *worker = (struct work_info *)kmalloc(sizeof(struct work_info), GFP_KERNEL);
            if (!worker && !kfifo_is_empty(*w_stack)) {
                void *worker_ptr;
                while (kfifo_out(*w_stack, &worker_ptr, sizeof(void *)) == sizeof(void *)) {
                    kfree(worker_ptr);
                }
                printk(KERN_ERR "Failed to allocate work_info structure\n");
                return -ENOMEM;
            }
            worker->cpu_id = cpu;
            worker->batch_start = i * BATCH_SIZE;

            INIT_WORK(&worker->work, wq_process_batch);
            // if (!kfifo_put(w_stack, &local_workers[i])) {
            //     printk(KERN_WARNING "KFIFO full, failed to enqueue worker\n");
            //     return -ENOMEM;
            // }
            if (kfifo_in(*w_stack, &worker, sizeof(void *)) != sizeof(void *)) {
                printk(KERN_WARNING "KFIFO full, failed to enqueue worker\n");
                return -ENOMEM;
            }
            printk(KERN_INFO "inserted worker on cpu:%d with batch: %d into kfifo\n", worker->cpu_id, worker->batch_start);
        }
    }

    return 0;
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
        // struct kmem_cache **cache = per_cpu_ptr(&packet_cache, cpu);
        // if (!cache || !*cache) {
        //     printk(KERN_WARNING "cpu:%d slab cache is not initialized\n", cpu);
        // }
        struct ring_buffer **rb_ptr = per_cpu_ptr(&percpu_circ_buf, cpu);
        struct ring_buffer *rb = *rb_ptr;
        if (!rb || !rb->buffer) {
            printk(KERN_WARNING "cpu:%d ring buffer is not initialized\n", cpu);
        }
        else {
            for (uint32_t i = 0; i < BUF_SIZE; i++) {
                void *p_info = rb->buffer[i];
                if (p_info) {
                    //free_packet_cache(*cache, data); NULL pointer bug for some reason
                    kfree(p_info);
                } else {
                    printk(KERN_WARNING "cpu:%d ring buffer entry %u is NULL\n", cpu, i);
                }
            }
            // destroy_packet_cache(*cache);
        }
    }
}

static void cancel_workers(void) {
    //cancel_delayed_work(&mac_dump_work);
    int cpu;
    for_each_possible_cpu(cpu) { 
        struct kfifo **w_stack_ptr = per_cpu_ptr(&worker_stack, cpu);
        if (!w_stack_ptr || !(*w_stack_ptr)) {
            printk(KERN_ERR "kfifo is NULL on cpu:%d\n", cpu);
        }
        else {
            struct kfifo *w_stack = *w_stack_ptr;
            void *worker_ptr;
            while (!kfifo_is_empty(w_stack) && kfifo_out(w_stack, &worker_ptr, sizeof(void *)) == sizeof(void *)) {
                if (!worker_ptr) {
                    printk(KERN_ERR "Invalid worker pointer for CPU %d, skipping...\n", cpu);
                    continue;
                }

                struct work_info *worker = (struct work_info *)worker_ptr;
                printk(KERN_INFO "removing worker for cpu:%d with batch start %d\n", cpu, worker->batch_start);

                cancel_work_sync(&worker->work);
                kfree(worker);
            }
        }
    }
}

static void free_kfifo(void) {
    int cpu;
    for_each_possible_cpu(cpu) {
        struct kfifo **w_stack_ptr = per_cpu_ptr(&worker_stack, cpu);
        if (!w_stack_ptr || !(*w_stack_ptr)) {
            printk(KERN_ERR "kfifo is NULL on cpu:%d\n", cpu);
        }
        else {
            struct kfifo *w_stack = *w_stack_ptr;
            if(!kfifo_is_empty(w_stack)) {
                void *worker_ptr;
                while (kfifo_out(w_stack, &worker_ptr, sizeof(void *)) == sizeof(void *)) {
                    kfree(worker_ptr);
                }
            }
            kfifo_free(w_stack);
        }
    }
}

static int __init logger_init(void) {
    nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if(!nfho) {
        printk(KERN_ERR "Failed to allocate memory for mac list\n");
        return -ENOMEM; 
    }
    mac_list = (struct mac_list *)kmalloc(sizeof(struct mac_list), GFP_KERNEL);
    if(!mac_list) {
        kfree(nfho);
        printk(KERN_ERR "Failed to allocate memory for mac list\n");
        return -ENOMEM; 
    }
    for (uint32_t i = 0; i < BUF_SIZE; i++) {
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
        cancel_workers();
        free_kfifo();
        clear_slab_caches();
        for (uint32_t j = 0; j < BUF_SIZE; j++) {
            kfree(mac_list->arr[j]);
        }
        kfree(mac_list);
        kfree(nfho);
        return -EINVAL;
    }
    printk(KERN_INFO "object_params: key len=%d, key offset=%zu, head offset=%zu\n", object_params.key_len, object_params.key_offset, object_params.head_offset);
    int ret = rhashtable_init(&rhash_frames, &object_params);
    if (ret) {
        cancel_workers();
        free_kfifo();   
        clear_slab_caches();
        for (uint32_t j = 0; j < BUF_SIZE; j++) {
            kfree(mac_list->arr[j]);
        }
        kfree(mac_list);
        kfree(nfho);
        printk(KERN_ERR "Error initializing hashtable: %d\n", ret);
        return ret;
    }
    init_hook(nfho, traffic_netdev_hook, NFPROTO_NETDEV, NF_NETDEV_INGRESS, NF_IP_PRI_FIRST);
    // int ret = nf_register_net_hook(&init_net, nfho); 
    // if (ret < 0) {
    //     cancel_workers();
    //     free_kfifo();
    //     clear_slab_caches();
    //     for (uint32_t j = 0; j < BUF_SIZE; j++) {
    //         kfree(mac_list->arr[j]);
    //     }
    //     kfree(mac_list);
    //     kfree(nfho);
    //     printk(KERN_ERR "Failed to register hook: %d\n", ret);
    //     return ret;
    // }
    // if(init_delayed_dump() < 0) {
    //     nf_unregister_net_hook(&init_net, nfho);
    //     cancel_delayed_work_sync(&mac_dump_work);
    //     cancel_workers();
    //     free_kfifo();
    //     clear_slab_caches();
    //     for (uint32_t j = 0; j < BUF_SIZE; j++) {
    //         kfree(mac_list->arr[j]);
    //     }
    //     kfree(mac_list);
    //     kfree(nfho);
    //     printk(KERN_ERR "Failed to schedule delay work (proc dumping)\n");
    //     return -ENOMEM;  
    // }

    printk(KERN_INFO "Traffic logger module loaded.\n");

    return 0;
}

static void __exit logger_exit(void) {
    // nf_unregister_net_hook(&init_net, nfho);
    // cancel_delayed_work_sync(&mac_dump_work);
    cancel_workers();
    free_kfifo();
    clear_slab_caches();

    struct rhashtable_iter iter;
    struct mac_info* obj = NULL;
    //atomic_inc(&reader_waiting);
    read_lock(&rhash_rwlock);
    rhashtable_walk_enter(&rhash_frames, &iter);
    rhashtable_walk_start(&iter);

    while ((obj = (struct mac_info*)rhashtable_walk_next(&iter)) != NULL) {
        if (IS_ERR(obj)) {
            printk(KERN_ERR "Error encountered while iterating hash table in log exit\n");
            continue;
        }
        if(rhashtable_remove_fast(&rhash_frames, &obj->linkage, object_params) == 0)
            kfree(obj);
        else {
            printk(KERN_WARNING "Cannot remove object from rhashtable");
        }
    }

    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

    read_unlock(&rhash_rwlock);
    //atomic_dec(&reader_waiting);

    for (uint32_t i = 0; i < BUF_SIZE; i++) {
        kfree(mac_list->arr[i]);
    }
    
    proc_remove(proc_file);
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