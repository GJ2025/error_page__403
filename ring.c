#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/shmem_fs.h>
#include <ring.h>
#include <ring_poll.h>

#define PROC_NAME "simple_int"  
#define ANON_FILE_SIZE (sizeof(ring_t)+4096)
static void *data = NULL;
static ring_t *g_ring = NULL;
struct file *g_anon_file = NULL;

static int anon_file_mmap(struct file *filp, struct vm_area_struct *vma) {
    unsigned long pfn;
    struct page *page;
    int ret;
    unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;

    if (offset >= ANON_FILE_SIZE) {
        return -EINVAL;
    }

    for (pfn = vma->vm_pgoff; pfn < (vma->vm_end - vma->vm_start) / PAGE_SIZE + vma->vm_pgoff; pfn++) {
        page = virt_to_page(filp->private_data + (pfn << PAGE_SHIFT));
        ret = vm_insert_page(vma, vma->vm_start + (pfn - vma->vm_pgoff) * PAGE_SIZE, page);
        if (ret) {
		return ret;
        }
    }

    return 0;
}

int anon_release (struct inode *a, struct file *b){

	printk("anon_release called:%p,%p\n",a,b);

	return 0;

}

int anon_file_flush(struct file *f, fl_owner_t id){

	printk("%s called, %p\n", __FUNCTION__, f);
	module_put(THIS_MODULE);
	return 0;
}



static struct file_operations anon_file_ops = {
    .owner = THIS_MODULE,
    .mmap = anon_file_mmap,
    .poll = anon_file_poll,
    .release = anon_release,
    .flush = anon_file_flush
};

static void init_ring(ring_t * ring){
	
	memset(ring, 0, sizeof(ring_t));
	ring->mask = 512-1;

	return;
}

static int __init anon_mmap_init(void) {
	g_ring = (ring_t *)kzalloc(ANON_FILE_SIZE, GFP_KERNEL);
	if (!g_ring) {
		printk(KERN_ERR "Failed to allocate memory\n");
        	return -ENOMEM;
    	}

	g_anon_file = shmem_file_setup("anon_mmap_file", ANON_FILE_SIZE, 0);
	if (IS_ERR(g_anon_file)) {
    		printk(KERN_ERR "Failed to create anonymous file, %p, %lu\n", g_anon_file, ANON_FILE_SIZE);
    		kfree(data);
    		return PTR_ERR(g_anon_file);
	}

	g_anon_file->f_op = &anon_file_ops;
	g_anon_file->private_data = (ring_t *)g_ring; 

	init_ring(g_ring);

	anon_dev_init();
	printk(KERN_INFO "Anonymous mmap file created successfully\n");
	return 0;
}

static void __exit anon_mmap_exit(void) {
    	printk(KERN_INFO "Module unloaded\n");
	anon_dev_exit();
}

static int ring_install_fd(struct file *file)
{       
        int fd;
       
	//printk(KERN_INFO "0:file->f_count(%p->%ld)", file, atomic_long_read(&file->f_count));

        fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
        if (fd < 0)
                return fd;

	//printk(KERN_INFO "1:file->f_count(%p->%ld)", file, atomic_long_read(&file->f_count));

	get_file(file);
        fd_install(fd, file);

	try_module_get(THIS_MODULE);

	//printk(KERN_INFO "2:file->f_count(%p->%ld)", file, atomic_long_read(&file->f_count));
	//printk(KERN_INFO "3: fd(%d)\n", fd);

	return fd;
}

static ssize_t simple_read(struct file *file, char __user *buf,
                          size_t count, loff_t *ppos) {
	int len;
	ring_fd_t ring_fd;

	memset(&ring_fd, 0, sizeof(ring_fd));

	if (*ppos > 0) return 0;

	ring_fd.fd =ring_install_fd(g_anon_file);		

	len = sizeof(ring_fd); 
    
	if (copy_to_user(buf, &ring_fd, len)) 
		return -EFAULT;
    
	*ppos = len;
	return len;
}

static const struct proc_ops proc_ops = {
    	.proc_read = simple_read
};

void __init ring_init(void) {
	anon_mmap_init();
	proc_create(PROC_NAME, 0444, NULL, &proc_ops); 
}

void __exit ring_exit(void) {
	anon_mmap_exit();
	remove_proc_entry(PROC_NAME, NULL);  
}

void ring_push(u32 saddr, u32 daddr){

	g_ring->ips[g_ring->tail & g_ring->mask].saddr = saddr;
	g_ring->ips[g_ring->tail & g_ring->mask].daddr = daddr;

	g_ring->tail++;

	printk("ring_push: head(%ld) tail(%ld)\n", g_ring->head, g_ring->tail);
	data_consumed_notify();
	return;

}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("guojian");
