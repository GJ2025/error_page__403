#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define PROC_NAME "simple_int"  
static int kernel_value = 123;  

static ssize_t simple_read(struct file *file, char __user *buf,
                          size_t count, loff_t *ppos) {
    int len;
    
    if (*ppos > 0) return 0;

    len = sizeof(kernel_value); 
    
    if (copy_to_user(buf, &kernel_value, len)) 
        return -EFAULT;
    
    *ppos = len;
    return len;
}

static const struct proc_ops proc_ops = {
    .proc_read = simple_read
};

void ring_init(void) {
    proc_create(PROC_NAME, 0444, NULL, &proc_ops);  
}

void ring_exit(void) {
    remove_proc_entry(PROC_NAME, NULL);  
}

EXPORT_SYMBOL(ring_init);
EXPORT_SYMBOL(ring_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("guojian");
