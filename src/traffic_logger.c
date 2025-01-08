#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/if_packet.h>
#include <linux/socket.h>
#include <net/sock.h>

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

static struct rhashtable *rhash_frames = NULL;
static DEFINE_RWLOCK(rhash_rwlock);
DEFINE_PER_CPU(struct ring_buffer *, percpu_circ_buf);
DEFINE_PER_CPU(atomic_t, batch_counter);
DEFINE_PER_CPU(atomic_t, skip_counter);
DEFINE_PER_CPU(struct kfifo *, worker_stack);
DEFINE_PER_CPU(spinlock_t, kfifo_slock);

static struct proc_dir_entry *proc_file;
static DECLARE_DELAYED_WORK(mac_dump_work, dump_htable);
static char *dump_buffer = NULL;
static size_t buffer_len;
static DEFINE_MUTEX(buffer_lock);

static ssize_t proc_read_cb(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    ssize_t ret;

    mutex_lock(&buffer_lock);
    if (!dump_buffer) {
        printk(KERN_WARNING "dump_buffer is not initialized\n");
        ret = -EINVAL;
    } else {
        ret = simple_read_from_buffer(buf, count, ppos, dump_buffer, buffer_len);
    }
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
    const unsigned char *key = (const unsigned char *)arg->key;
    const struct mac_info *mi = (const struct mac_info *)obj;

    if (memcmp(key, mi->src_mac_key, ETH_ALEN) == 0)
        return 0;

    return -ESRCH;
}

static const struct rhashtable_params object_params = {
    .key_len     = ETH_ALEN,
    .key_offset  = offsetof(struct mac_info, src_mac_key),
    .head_offset = offsetof(struct mac_info, linkage),
    .hashfn      = mac_hashfn,
    .obj_cmpfn   = mac_obj_cmpfn,
};

static int insert_mac_info(struct rhashtable *ht, const unsigned char *mac_str)
{
    struct mac_info *mi = kmalloc(sizeof(*mi), GFP_ATOMIC);
    if (!mi) {
        printk(KERN_ERR "failed to allocate mac_info\n");
        return -ENOMEM;
    }

    memcpy(mi->src_mac_key, mac_str, ETH_ALEN);
    memcpy(mi->src_mac, mac_str, ETH_ALEN);
    refcount_set(&mi->ref, 1);

    struct mac_info *old = rhashtable_lookup_get_insert_fast(ht, &mi->linkage, object_params);
    if (IS_ERR(old)) {
        printk(KERN_ERR "insertion failed\n");
        return -1;
    } else if (old) {
        printk(KERN_INFO "duplicate mac address was found\n");
        return 1;
    }

    return 0;
}

static void remove_objects(struct rhashtable *ht)
{
    struct rhashtable_iter iter;
    struct mac_info *obj = NULL;
    rhashtable_walk_enter(ht, &iter);
    rhashtable_walk_start(&iter);

    while ((obj = (struct mac_info *)rhashtable_walk_next(&iter)) != NULL) {
        if (IS_ERR(obj)) {
            if (PTR_ERR(obj) == -EAGAIN) {
                printk(KERN_ERR "Error encountered while iterating got EAGAIN: %ld\n", PTR_ERR(obj));
                break;
            }
            printk(KERN_ERR "Error encountered while iterating hash table: %ld\n", PTR_ERR(obj));
            break;
        }
        if (!obj) {
            printk(KERN_ERR "Received NULL object pointer while iterating\n");
            break;
        }

        rcu_read_lock();
        if (rhashtable_remove_fast(ht, &obj->linkage, object_params) == 0) {
            refcount_set(&obj->ref, 0);
            kfree_rcu(obj, rcu_read);
        } 
        rcu_read_unlock();
    }

    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);
}

void dump_htable(struct work_struct *work) {
    struct rhashtable_iter iter;

    if (!dump_buffer) {
        dump_buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
        if (!dump_buffer) {
            printk(KERN_ERR "failed to allocate dump_buffer\n");
            return;
        }
    } else {
        memset(dump_buffer, 0, PAGE_SIZE);
    }

    mutex_lock(&buffer_lock);
    synchronize_rcu();
    rcu_read_lock();
    
    rhashtable_walk_enter(rhash_frames, &iter);
    rhashtable_walk_start(&iter);
    uint32_t i = 0;
    size_t offset = 0;
    struct mac_info* obj = NULL;
    while ((obj = (struct mac_info *)rhashtable_walk_next(&iter)) != NULL) {
        if (IS_ERR(obj)) {
            if (PTR_ERR(obj) == -EAGAIN) {
                printk(KERN_ERR "Error encountered while iterating got EAGAIN: %ld\n", PTR_ERR(obj));
                break;
            }
            printk(KERN_ERR "Error encountered while iterating hash table: %ld\n", PTR_ERR(obj));
            break;
        }
        if (!obj) {
            printk(KERN_ERR "Received NULL object pointer while iterating\n");
            break;
        }

        offset += scnprintf(dump_buffer + offset, PAGE_SIZE - offset,
                            "%02x:%02x:%02x:%02x:%02x:%02x\n",
                            obj->src_mac[0], obj->src_mac[1], obj->src_mac[2],
                            obj->src_mac[3], obj->src_mac[4], obj->src_mac[5]);

        if (offset >= PAGE_SIZE) {
            pr_warn("MAC dump truncated due to buffer size\n");
            break;
        }

        i++;
    }
    buffer_len = offset;
    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);
    
    rcu_read_unlock();
    mutex_unlock(&buffer_lock);
    remove_objects(rhash_frames);

    printk(KERN_INFO "Periodic MAC dump completed and accounting reset (%zu bytes)\n", buffer_len);
    schedule_delayed_work(&mac_dump_work, msecs_to_jiffies(DUMP_PERIOD));
}

static int init_delayed_dump(void) {
    proc_file = proc_create("mac_dump", 0444, NULL, &proc_fops);
    if (!proc_file) {
        printk(KERN_ERR "Failed to create /proc/mac_dump\n");
        return -ENOMEM;
    }

    schedule_delayed_work(&mac_dump_work, msecs_to_jiffies(DUMP_PERIOD));
    printk(KERN_INFO "mac_dump initialized\n");
    return 0;
}

static void* dequeue_circ_buf(struct ring_buffer *rb) {
    if(rb->head == -1)//no more space for incoming frame
        return NULL;
    if(!rb->buffer[rb->head]) {
        printk(KERN_WARNING "Dequeued null data from ring buffer\n");
        return NULL;
    }
    void* data = rb->buffer[rb->head];
    int next_head = (rb->head + 1) % BUF_SIZE;
    rb->head = next_head;

    return data;
}

static void wq_process_batch(struct work_struct *work_ptr) {
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

    for(uint32_t i = start_index; i < BATCH_SIZE + start_index; i++) {
        struct packet_info *p_info = (struct packet_info *)rb->buffer[i];
        const void *key = p_info->eth_h.h_source;
        rcu_read_lock();
        struct mac_info *found = (struct mac_info *)rhashtable_lookup_fast(rhash_frames, key, object_params);
        rcu_read_unlock(); 

        if (found) {
            continue;
        }

        write_lock(&rhash_rwlock);
    
        if(insert_mac_info(rhash_frames, p_info->eth_h.h_source) < 0) {
            spin_lock(s_lock);
            if (kfifo_in(w_stack, &w_info, sizeof(void *)) != sizeof(void *)) {
                printk(KERN_WARNING "KFIFO full, failed to enqueue worker\n");
            }
            
            if(rb->head == -1)
                rb->head = start_index;
            spin_unlock(s_lock);
            write_unlock(&rhash_rwlock);
            printk(KERN_ERR "Failed to allocate memory in batch processor\n");
            continue;
        }
        
        write_unlock(&rhash_rwlock);
    }
    spin_lock(s_lock);
    if (kfifo_in(w_stack, &w_info, sizeof(void *)) != sizeof(void *)) {
        printk(KERN_WARNING "KFIFO full, failed to enqueue worker\n");
    }
    if(rb->head == -1)
        rb->head = start_index;
    spin_unlock(s_lock);
}

static struct packet_type p_type = {
    .type = htons(ETH_P_ALL),
    .dev = NULL,
    .func = packet_rcv
};

static int packet_rcv(struct sk_buff *skb, struct net_device *dev,
                      struct packet_type *p_type, struct net_device *orig_dev) {
    struct ethhdr* eth_h = eth_hdr(skb);
    if(!eth_h) {
        printk(KERN_INFO "failed to capture ethernet or ip header in traffic_logger module\n");
        return NET_RX_SUCCESS;
    }

    int proto_hs = ntohs(eth_h->h_proto);
    if(!whitelist_proto[proto_hs]) {
        return NET_RX_SUCCESS;
    }

    atomic_t *b_counter = this_cpu_ptr(&batch_counter);
    struct ring_buffer **rb_ptr = this_cpu_ptr(&percpu_circ_buf);
    struct ring_buffer *rb = *rb_ptr;

    struct packet_info *p_info = (struct packet_info *)dequeue_circ_buf(rb);
    if(!p_info) {
        return NET_RX_SUCCESS;
    }
    memcpy(&p_info->eth_h, eth_h, sizeof(struct ethhdr));

    atomic_inc(b_counter);
    int counter = atomic_read(b_counter);
    if(counter % BATCH_SIZE == 0) {
        atomic_set(b_counter, 0);
        struct kfifo **w_stack_ptr = this_cpu_ptr(&worker_stack);
        if (!w_stack_ptr || !(*w_stack_ptr)) {
            printk(KERN_ERR "[traffic_netdev_hook] kfifo is NULL:%d\n");
            return NET_RX_SUCCESS;
        }
        struct kfifo *w_stack = *w_stack_ptr;

        spinlock_t *s_lock = this_cpu_ptr(&kfifo_slock);

        spin_lock(s_lock);
        void *worker_ptr;
        if (kfifo_out(w_stack, &worker_ptr, sizeof(void *)) != sizeof(void *)) {
            printk(KERN_WARNING "[traffic_netdev_hook] kfifo is empty, failed to pop worker\n");
            return NET_RX_SUCCESS;
        }
        struct work_info *worker = (struct work_info *)worker_ptr;
        
        void *worker_ptr_next;
        if (kfifo_out_peek(w_stack, &worker_ptr_next, sizeof(void *)) != sizeof(void *)) {
            rb->head = -1;
        } else {
            struct work_info *worker_next = (struct work_info *)worker_ptr_next;
            rb->head = worker_next->batch_start;
        }

        spin_unlock(s_lock);
        if (!schedule_work_on(worker->cpu_id, &worker->work)) {
            printk(KERN_WARNING "Failed to queue work in workqueue\n");
        }
    }

    return NET_RX_SUCCESS;
}

static int init_per_cpu(void) {
    int cpu;
    for_each_possible_cpu(cpu) {
        int res = 0;
        struct ring_buffer **rb = per_cpu_ptr(&percpu_circ_buf, cpu);
        *rb = (struct ring_buffer *)kmalloc(sizeof(struct ring_buffer), GFP_KERNEL);
        if (!*rb) {
            printk(KERN_ERR "Failed to allocate memory for ring buffer per cpu %d\n", cpu);
            return -ENOMEM;
        }
        (*rb)->head = 0;
        (*rb)->tail = 0;
        for(uint32_t i = 0; i < BUF_SIZE; i++) {
            struct packet_info *p_info = (struct packet_info *)kmalloc(sizeof(struct packet_info), GFP_KERNEL);
            if(!p_info) {
                printk(KERN_ERR "[kmalloc] Cannot allocate memory for packet during init due to ring buffer error\n");
                return -1;
            }
            (*rb)->buffer[i] = p_info;
        }

        atomic_t *b_counter = per_cpu_ptr(&batch_counter, cpu);
        atomic_set(b_counter, 0);

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
            if (kfifo_in(*w_stack, &worker, sizeof(void *)) != sizeof(void *)) {
                printk(KERN_WARNING "KFIFO full, failed to enqueue worker\n");
                return -ENOMEM;
            }
            printk(KERN_INFO "inserted worker on cpu:%d with batch: %d into kfifo\n", worker->cpu_id, worker->batch_start);
        }
    }

    return 0;
}

static void free_ringbuffers(void) {
    int cpu;

    for_each_possible_cpu(cpu) { 
        struct ring_buffer **rb_ptr = per_cpu_ptr(&percpu_circ_buf, cpu);
        struct ring_buffer *rb = *rb_ptr;
        if (!rb || !rb->buffer) {
            printk(KERN_WARNING "cpu:%d ring buffer is not initialized\n", cpu);
        }
        else {
            for (uint32_t i = 0; i < BUF_SIZE; i++) {
                void *p_info = rb->buffer[i];
                if (p_info) {
                    kfree(p_info);
                } else {
                    printk(KERN_WARNING "cpu:%d ring buffer entry %u is NULL\n", cpu, i);
                }
            }
        }
    }
}

static void cancel_workers(void) {
    cancel_delayed_work(&mac_dump_work);
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
    if (init_per_cpu() < 0) {
        cancel_workers();
        free_kfifo();
        free_ringbuffers();
        return -EINVAL;
    }
    printk(KERN_INFO "object_params: key len=%d, key offset=%zu, head offset=%zu\n", object_params.key_len, object_params.key_offset, object_params.head_offset);
    rhash_frames = kmalloc(sizeof(struct rhashtable), GFP_KERNEL);
    if(!rhash_frames) {
        printk(KERN_ERR "Error allocating memory for hashtable\n");
        return -ENOMEM;
    }
    int ret = rhashtable_init(rhash_frames, &object_params);
    if (ret) {
        cancel_workers();
        free_kfifo();   
        free_ringbuffers();
        kfree(rhash_frames);
        printk(KERN_ERR "Error initializing hashtable: %d\n", ret);
        return ret;
    }
    dev_add_pack(&p_type);
    if(init_delayed_dump() < 0) {
        dev_remove_pack(&p_type);
        cancel_delayed_work_sync(&mac_dump_work);
        cancel_workers();
        free_kfifo();
        free_ringbuffers();
        kfree(rhash_frames);
        printk(KERN_ERR "Failed to schedule delay work (proc dumping)\n");
        return -ENOMEM;  
    }

    printk(KERN_INFO "Traffic logger module loaded.\n");

    return 0;
}

static void __exit logger_exit(void) {
    dev_remove_pack(&p_type);
    cancel_delayed_work_sync(&mac_dump_work);
    cancel_workers();
    free_kfifo();
    free_ringbuffers();
    remove_objects(rhash_frames);
    proc_remove(proc_file);
    if(!dump_buffer)
        kfree(dump_buffer);
    printk(KERN_INFO "Traffic logger module Unloaded.\n");
}

module_init(logger_init);
module_exit(logger_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Den/M22");
MODULE_DESCRIPTION("Packet logger");