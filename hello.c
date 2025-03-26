#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


static unsigned redirect(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){

	printk(KERN_INFO "%s start \n", __FUNCTION__);
	return NF_ACCEPT;

}

static struct nf_hook_ops net_hooks[] = {
	{
		.hook = redirect,
		.pf   = NFPROTO_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST,
	}
};

static int __init hello_init(void) {  
	int ret = 0;
	printk(KERN_INFO "Hello, Debian 12 kernel module!\n");  
    
	ret = nf_register_net_hooks(&init_net, net_hooks,ARRAY_SIZE(net_hooks));

	return 0;  
}  

static void __exit hello_exit(void) { 

	nf_unregister_net_hooks(&init_net, net_hooks, ARRAY_SIZE(net_hooks));	
	printk(KERN_INFO "Goodbye, kernel module!\n");  
}  

module_init(hello_init);  
module_exit(hello_exit);  
MODULE_LICENSE("GPL");  
MODULE_AUTHOR("guojian");  
