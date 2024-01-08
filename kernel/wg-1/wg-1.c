/* 
 * wg-1.c - This hook prints all packets with src/dest IP of ifconfig.me. 
 */ 
#include <linux/module.h> /* Needed by all modules */ 
#include <linux/printk.h> /* Needed for pr_info() */ 
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip_tunnels.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>

#define DEBUG 0

// POSTROUTING packets
static struct nf_hook_ops nfho_postrouting;
// PREROUTING packets
static struct nf_hook_ops nfho_prerouting;
// FORWARD packets
static struct nf_hook_ops nfho_forward;
// INPUT packets
static struct nf_hook_ops nfho_input;
// OUTPUT packets
static struct nf_hook_ops nfho_output;

static unsigned int hook_func_common(struct sk_buff *skb, const struct nf_hook_state *state, const char *chain)
{
	struct iphdr *iph;
	uint8_t *saddr, *daddr;
	char *in, *out;

	if (!skb)
		return NF_ACCEPT;
	
	iph = ip_hdr(skb);
	if (iph) {
		// ifconfig.me: 34.117.228.44
		if (iph->saddr == 0x2c767522 || iph->daddr == 0x2c767522) {
			saddr = (uint8_t*)&(iph->saddr);
			daddr = (uint8_t*)&(iph->daddr);
			if (state && state->in)
				in = state->in->name;
			else
				in = "NULL";
			if (state && state->out)	
				out = state->out->name;
			else
				out = "NULL";
			printk(KERN_INFO "Got a packet from in %s chain: in=%s, out=%s, protocol=%u, srcAddr=%u.%u.%u.%u, destAddr=%u.%u.%u.%u\n", chain, in, out, iph->protocol, saddr[0], saddr[1], saddr[2], saddr[3], daddr[0], daddr[1], daddr[2], daddr[3]);
		}
	}

	return NF_ACCEPT;
}

//POSTROUTING for outgoing packets
static unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return hook_func_common(skb, state, "POSTROUTING");
}

//PREROUTING for incoming packets
static unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return hook_func_common(skb, state, "PREROUTING");
}

// FORWARD packets
static unsigned int hook_func_forward(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return hook_func_common(skb, state, "FORWARD");
}

// INPUT packets
static unsigned int hook_func_input(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return hook_func_common(skb, state, "INPUT");
}

// OUTPUT packets
static unsigned int hook_func_output(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return hook_func_common(skb, state, "OUTPUT");
}

int wg_init(void)
{
	//POSTROUTING
	nfho_postrouting.hook = (nf_hookfn*)hook_func_out;	//function to call when conditions below met
	nfho_postrouting.hooknum = NF_INET_POST_ROUTING;	//called in post_routing
	nfho_postrouting.pf = PF_INET;	//IPV4 packets
	nfho_postrouting.priority = NF_IP_PRI_FIRST;	//set to highest priority over all other hook functions
	nf_register_net_hook(&init_net, &nfho_postrouting);	//register hook

	//PREROUTING
	nfho_prerouting.hook = (nf_hookfn*)hook_func_in;                    //function to call when conditions below met
	nfho_prerouting.hooknum = NF_INET_PRE_ROUTING;          //called in pre_routing
	nfho_prerouting.pf = PF_INET;                           //IPV4 packets
	nfho_prerouting.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
	nf_register_net_hook(&init_net, &nfho_prerouting);                     //register hook

	//FORWARD
	nfho_forward.hook = (nf_hookfn*)hook_func_forward;                    //function to call when conditions below met
	nfho_forward.hooknum = NF_INET_FORWARD;          //called in forward
	nfho_forward.pf = PF_INET;                           //IPV4 packets
	nfho_forward.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
	nf_register_net_hook(&init_net, &nfho_forward);                     //register hook

	//INPUT
	nfho_input.hook = (nf_hookfn*)hook_func_input;                    //function to call when conditions below met
	nfho_input.hooknum = NF_INET_LOCAL_IN;          //called in input
	nfho_input.pf = PF_INET;                           //IPV4 packets
	nfho_input.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
	nf_register_net_hook(&init_net, &nfho_input);                     //register hook

	//OUTPUT
	nfho_output.hook = (nf_hookfn*)hook_func_output;                    //function to call when conditions below met
	nfho_output.hooknum = NF_INET_LOCAL_OUT;          //called in output
	nfho_output.pf = PF_INET;                           //IPV4 packets
	nfho_output.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
	nf_register_net_hook(&init_net, &nfho_output);                     //register hook

	printk(KERN_INFO "Register Netfilter hooks\n");
	return 0;
}

void wg_exit(void)
{
	nf_unregister_net_hook(&init_net, &nfho_postrouting);
	nf_unregister_net_hook(&init_net, &nfho_prerouting);
	nf_unregister_net_hook(&init_net, &nfho_forward);
	nf_unregister_net_hook(&init_net, &nfho_input);
	nf_unregister_net_hook(&init_net, &nfho_output);

	printk(KERN_INFO "Unregister Netfilter hooks\n");
}

module_init(wg_init);
module_exit(wg_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wantong Jiang wantjian@microsoft.com");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Kernel module of wg packet analysis");
