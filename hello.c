#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/kernel.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


static unsigned redirect(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){

	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	unsigned int sip = 0;
	unsigned int dip = 0;
	unsigned short sport = 0;
	unsigned short dport = 0;
	char *payload = NULL;


	if (skb == NULL || skb->pkt_type == PACKET_BROADCAST || skb->len < 20){
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);

	if (iph == NULL || iph->version != 4 || !(iph->frag_off & htons(IP_DF)) || iph->protocol != 6){
		return NF_ACCEPT;
	}

	sip = iph->saddr;
	dip = iph->daddr;

	tcph = tcp_hdr(skb);
	if (tcph == NULL){
		return NF_ACCEPT;
	}

	sport = ntohs(tcph->source);
	dport = ntohs(tcph->dest);

	if (dport != 8008){
		return NF_ACCEPT;
	}

	payload = (char *)tcph + tcp_hdrlen(skb);

	if (payload[0] != 'G' || payload[1] != 'E' || payload[2] != 'T'){
		return NF_ACCEPT;
	}


	printk(KERN_INFO "%s: <%pI4:%d to %pI4:%d> \n", __FUNCTION__, &sip, sport, &dip,dport);
	printk(KERN_INFO "%.*s\n", ip_transport_len(skb) - tcp_hdrlen(skb), payload);

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
