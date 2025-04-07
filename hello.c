#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/kernel.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <ring.h>

char *page_body =
"<html>\r\n" 
"<head><title>403 Forbidden</title></head>\r\n"
"<body>\r\n"
"<center><h1>403 Forbidden</h1></center>\r\n";

char *msg = NULL;

char *new_403_Page(void)
{
	unsigned int size = 0;
	int page_body_size = 0;
	char *page_all = NULL;

	size += 256;

	page_body_size = strlen(page_body);

	size += page_body_size;

	page_all = kmalloc(size, GFP_KERNEL);
	memset(page_all, 0, size);

	snprintf(page_all, size, "HTTP/1.1 403 forbiden\r\n"
			"Content-Type: text/html\r\n"
			"Content-length: %d\r\n\r\n"
			"%s", 
			page_body_size,
			page_body);

	return page_all;
}


struct sk_buff *tcp_newpacket(u32 saddr, u32 daddr, u16 sport, u16 dport, u32 seq, u32 ack, u8 *msg, u32 len){

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

	/*copy http data*/
	memcpy(skb_put(skb,len), msg, len);
	
	/*new tcp header*/
	skb_push(skb, sizeof(*tcph));
	skb_reset_transport_header(skb);
	tcph = tcp_hdr(skb);


	memset(tcph, 0, sizeof(tcph));
	tcph->doff = 5;
	tcph->source = sport;
	tcph->dest = dport;
	tcph->seq = seq;
	tcph->ack_seq = ack;
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
	
	printk("syn, ack -> %u, %u", ntohl(seq), ntohl(ack));

	skb_push(skb, sizeof(*iph));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);

	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = htons(iplen);
	iph->id = 0;
	iph->frag_off = htons(IP_DF);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = saddr;
	iph->daddr = daddr;

	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
		



	return skb;
}

static unsigned redirect(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){

	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct ethhdr *ethh = NULL;
	unsigned int sip = 0;
	unsigned int dip = 0;
	unsigned short sport = 0;
	unsigned short dport = 0;
	char *payload = NULL;
	u32 tcplen = 0;
	u32 syn = 0;
	u32 ack = 0;
	struct sk_buff *skb_1 = NULL;

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

	if (dport != 80){
		return NF_ACCEPT;
	}

	payload = (char *)tcph + tcp_hdrlen(skb);

	if (payload[0] != 'G' || payload[1] != 'E' || payload[2] != 'T'){
		return NF_ACCEPT;
	}

	tcplen = ip_transport_len(skb) - tcp_hdrlen(skb);

	printk("tcplen: %u, network order tcph.seq: %u, local host tcp.seq: %u\n", tcplen, tcph->seq, ntohl(tcph->seq));

	ack = ntohl(tcph->seq) + tcplen;

	printk("tcplen: %u, ack: %u\n", tcplen, ack);

	ack = htonl(ack);

	syn = tcph->ack_seq;

	skb_1 = tcp_newpacket(dip, sip, tcph->dest, tcph->source, syn, ack, msg, strlen(msg)); 

	ethh = (struct ethhdr *)skb_push(skb_1, ETH_HLEN);
	skb_reset_mac_header(skb_1);

	skb_1->protocol = eth_hdr(skb)->h_proto;
	ethh->h_proto = eth_hdr(skb)->h_proto;

	memcpy(ethh->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);
	memcpy(ethh->h_dest, eth_hdr(skb)->h_source, ETH_ALEN);

	if (skb->dev){
		skb_1->dev = skb->dev;
		dev_queue_xmit(skb_1);

		printk(KERN_INFO "dev_queue_xmit is called\n");
	}else{
		printk(KERN_INFO "skb->dev is NULLLLLLLLLLLLLLLLLLLL\n");
	}



	printk(KERN_INFO "%s: <%pI4:%d to %pI4:%d> \n", __FUNCTION__, &sip, sport, &dip,dport);
	printk(KERN_INFO "%.*s\n", tcplen, payload);

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

	msg = new_403_Page(); 

	ring_init();
	ret = nf_register_net_hooks(&init_net, net_hooks,ARRAY_SIZE(net_hooks));

	return 0;  
}  

static void __exit hello_exit(void) { 

	nf_unregister_net_hooks(&init_net, net_hooks, ARRAY_SIZE(net_hooks));	
	if (msg){
		kfree(msg);
		msg = NULL;
	}
	
	ring_exit();
	printk(KERN_INFO "Goodbye, kernel module!\n");  
}  

module_init(hello_init);  
module_exit(hello_exit);  
MODULE_LICENSE("GPL");  
MODULE_AUTHOR("guojian");  
