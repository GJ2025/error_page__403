
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/shmem_fs.h>
#include <linux/poll.h>

#include<ring.h>
#include<ring_poll.h>

struct anon_dev * g_anon_dev = NULL;


int __init anon_dev_init(void)
{
    g_anon_dev = kzalloc(sizeof(struct anon_dev), GFP_KERNEL);
    if (!g_anon_dev) {
        pr_err("Failed to allocate anonymous device\n");
        return -ENOMEM;
    }

    init_waitqueue_head(&g_anon_dev->readq);

    spin_lock_init(&g_anon_dev->lock);

    printk(KERN_INFO "Anonymous device initialized\n");
    return 0;
}

__poll_t anon_file_poll(struct file *filp, poll_table *wait) {
    ring_t *ring = filp->private_data;
    __poll_t mask = 0;

	printk("anon_file_poll called and g_anon_dev(%p)", g_anon_dev);

    poll_wait(filp, &g_anon_dev->readq, wait);

	smp_rmb();
    if (ring->tail != ring->head)
    	mask |= EPOLLIN | EPOLLRDNORM;  
printk("%s call with tail(%ld),head(%ld),poll_mask(%d)","YES POLL_WAIT", ring->tail, ring->head, mask);

    return mask;
}


void data_consumed_notify(void) {
    //wake_up_interruptible(&g_anon_dev->readq);
    wake_up_interruptible_sync_poll(&g_anon_dev->readq, EPOLLIN);
}

void __exit anon_dev_exit(void)
{
    if (g_anon_dev) {
        kfree(g_anon_dev);
        g_anon_dev = NULL;
    }
    printk(KERN_INFO "Anonymous device removed\n");
}


//EXPORT_SYMBOL(anon_file_poll);
//EXPORT_SYMBOL(anon_dev_init);
//EXPORT_SYMBOL(anon_dev_exit);
//EXPORT_SYMBOL(data_consumed_notify);
