#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/kernel.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


struct sk_buff *tcp_newpacket(u32 saddr, u32 daddr, u16 sport, u16 dport, u32 seq, u32 ack_seq, u8 *msg, u32 len){

	struct iphdr *iph;
	struct tcphdr *tcph;
	struct sk_buff *skb;
	int iplen = 0;
	int tcplen = 0;
	int ethlen = 0;
	int headerlen = 0;
	__wsum tcp_hdr_csum;

	tcplen = len+sizeof(struct tcphdr);
	iplen = tcplen+sizeof(struct iphdr);
	ethlen = iplen+ETH_HLEN;
	headerlen = ethlen - len;

	skb = alloc_skb(ethlen, GFP_ATOMIC);

	skb_reserve(skb, headerlen);

	memcpy(skb_put(skb,len), msg, len);
	
	skb_push(skb, sizeof(*tcph));
	skb_reset_transport_header(skb);
	tcph = tcp_hdr(skb);


	memset(tcph, 0, sizeof(tcph));
	tcph->doff = 5;
	tcph->source = sport;
	tcph->dest = dport;
	tcph->seq = seq;
	tcph->ack_seq = ack_seq;
	tcph->urg_ptr = 0;
	tcph->psh = 1;
	tcph->ack = 1;
	tcph->window = htons(63857);
	tcph->check = 0;

	tcp_hdr_csum = csum_partial(tcph, tcplen, 0);
	tcph->check = csum_tcpudp_magic(saddr, daddr, tcplen, IPPROTO_TCP, tcp_hdr_csum);
	skb->csum = tcp_hdr_csum;

	if (tcph->check == 0){
		printk("tcph checksum is 0000000000000000\n");
	} 
	

	



	return NULL;
}

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
