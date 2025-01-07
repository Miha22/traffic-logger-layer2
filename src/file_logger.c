#include <file_logger.h>

static struct mac_list *mac_list;
static struct proc_dir_entry *proc_file;
static struct workqueue_struct *mac_dump_wq;
static struct delayed_work mac_dump_work;

static int dump2proc(struct seq_file *m, void *v)
{
    for (uint32_t i = 0; i < mac_list->len; i++) {
        seq_printf(m, "%pM\n", mac_list->arr[i]);
    }
    return 0;
}

static int dump_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, dump2proc, NULL);
}

static const struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .open = dump_proc_open,
    .read = seq_read,
    .release = single_release,
};

static void wq_process_dump(struct work_struct *work)
{
    for (uint32_t i = 0; i < mac_list->len; i++) {
        unsigned char *mac = kzalloc(ETH_ALEN, GFP_KERNEL);
        snprintf(mac, ETH_ALEN, "%02x:%02x:%02x:%02x:%02x:%02x",
                 i, i, i, i, i, i);
        mac_list->arr[mac_list->len++] = mac;
    }

    schedule_delayed_work(&mac_dump_work, msecs_to_jiffies(DUMP_PERIOD));
}

static int init_delayed_dump(struct mac_list *m_list) {
    mac_dump_wq = create_workqueue("mac_dump_wq");
    if (!mac_dump_wq) {
        pr_err("Failed to create work queue\n");
        return -ENOMEM;
    }

    mac_list = m_list;
    INIT_DELAYED_WORK(&mac_dump_work, wq_process_dump);

    proc_file = proc_create("mac_dump", 0, NULL, &proc_fops);
    if (!proc_file) {
        pr_err("Failed to create /proc/mac_dump\n");
        destroy_workqueue(mac_dump_wq);
        return -ENOMEM;
    }

    schedule_delayed_work(&mac_dump_work, msecs_to_jiffies(DUMP_PERIOD));
}