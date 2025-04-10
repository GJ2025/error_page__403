
#include <linux/poll.h>
#include <linux/spinlock.h>

struct anon_dev {
    wait_queue_head_t readq;  
    spinlock_t lock;             
};

void __exit anon_dev_exit(void);
void data_consumed_notify(void);
__poll_t anon_file_poll(struct file *filp, poll_table *wait);
int __init anon_dev_init(void);
