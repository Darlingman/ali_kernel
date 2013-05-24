/*
 *  skbtrace - sk_buff trace utilty
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * 2012 Li Yu <bingtian.ly@taobao.com>
 *
 */

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/skbtrace_api.h>
#include <linux/skbtrace.h>

static struct skbtrace_tracepoint common[];
#define tracepoint_skb_rps    (&common[0])

struct flow_keys {
        /* (src,dst) must be grouped, in the same way than in IP header */
        __be32 src;
        __be32 dst;
        union {
                __be32 ports;
                __be16 port16[2];
        };
        u8 ip_proto;
};


static bool skb_flow_dissect(const struct sk_buff *skb, struct flow_keys *flow);

static void skbtrace_skb_rps_info(struct sk_buff *skb, struct net_device *dev, int cpu)
SKBTRACE_SKB_EVENT_BEGIN
	struct skbtrace_tracepoint *t = tracepoint_skb_rps;
	struct skbtrace_skb_rps_info_blk blk, *b;
	struct flow_keys keys;

	b = skbtrace_block_get(t, NULL, &blk);
	INIT_SKBTRACE_BLOCK(&b->blk, skb,
			skbtrace_action_skb_rps_info,
			0,
			sizeof(blk));
	b->rx_hash = skb->rxhash;
	if (skb_rx_queue_recorded(skb))
		b->rx_queue = skb_get_rx_queue(skb);
	else
		b->rx_queue = 0;
	skb_flow_dissect(skb, &keys);
	b->keys.src = keys.src;
	b->keys.dst = keys.dst;
	b->keys.ports = keys.ports;
	b->keys.ip_proto = keys.ip_proto;
	b->cpu = cpu;
	b->ifindex = dev->ifindex;
	skbtrace_probe(t, NULL, &b->blk);
SKBTRACE_SKB_EVENT_END

static struct skbtrace_tracepoint common[] = {
	{
		.trace_name = "skb_rps_info",
		.action = skbtrace_action_skb_rps_info,
		.block_size = sizeof(struct skbtrace_skb_rps_info_blk),
		.probe = skbtrace_skb_rps_info,
	},
	EMPTY_SKBTRACE_TP
};

int skbtrace_events_common_init(void)
{
	return skbtrace_register_proto(AF_UNSPEC, common, NULL);
}

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_vlan.h>
#include <net/ip.h>
#include <linux/if_tunnel.h>
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>

static inline bool ip_is_fragment(const struct iphdr *iph)
{
        return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}

/* copy saddr & daddr, possibly using 64bit load/store
 *  * Equivalent to :      flow->src = iph->saddr;
 *   *                      flow->dst = iph->daddr;
 *    */     
static void iph_to_flow_copy_addrs(struct flow_keys *flow, const struct iphdr *iph)
{
        BUILD_BUG_ON(offsetof(typeof(*flow), dst) !=
                     offsetof(typeof(*flow), src) + sizeof(flow->src));
        memcpy(&flow->src, &iph->saddr, sizeof(flow->src) + sizeof(flow->dst));
}

static inline int proto_ports_offset(int proto)
{
        switch (proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_DCCP:
        case IPPROTO_ESP:       /* SPI */
        case IPPROTO_SCTP:
        case IPPROTO_UDPLITE:
                return 0;
        case IPPROTO_AH:        /* SPI */
                return 4;
        default:
                return -EINVAL;
        }       
}

static bool skb_flow_dissect(const struct sk_buff *skb, struct flow_keys *flow)
{
	int poff, nhoff = skb_network_offset(skb);
	u8 ip_proto;
	__be16 proto = skb->protocol;

	memset(flow, 0, sizeof(*flow));

again:
	switch (proto) {
	case __constant_htons(ETH_P_IP): {
		const struct iphdr *iph;
		struct iphdr _iph;
ip:
		iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
		if (!iph)
			return false;

		if (ip_is_fragment(iph))
			ip_proto = 0;
		else
			ip_proto = iph->protocol;
		iph_to_flow_copy_addrs(flow, iph);
		nhoff += iph->ihl * 4;
		break;
	}
	case __constant_htons(ETH_P_IPV6): {
		const struct ipv6hdr *iph;
		struct ipv6hdr _iph;
ipv6:
		iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
		if (!iph)
			return false;

		ip_proto = iph->nexthdr;
		flow->src = iph->saddr.s6_addr32[3];
		flow->dst = iph->daddr.s6_addr32[3];
		nhoff += sizeof(struct ipv6hdr);
		break;
	}
	case __constant_htons(ETH_P_8021Q): {
		const struct vlan_hdr *vlan;
		struct vlan_hdr _vlan;

		vlan = skb_header_pointer(skb, nhoff, sizeof(_vlan), &_vlan);
		if (!vlan)
			return false;

		proto = vlan->h_vlan_encapsulated_proto;
		nhoff += sizeof(*vlan);
		goto again;
	}
	case __constant_htons(ETH_P_PPP_SES): {
		struct {
			struct pppoe_hdr hdr;
			__be16 proto;
		} *hdr, _hdr;
		hdr = skb_header_pointer(skb, nhoff, sizeof(_hdr), &_hdr);
		if (!hdr)
			return false;
		proto = hdr->proto;
		nhoff += PPPOE_SES_HLEN;
		switch (proto) {
		case __constant_htons(PPP_IP):
			goto ip;
		case __constant_htons(PPP_IPV6):
			goto ipv6;
		default:
			return false;
		}
	}
	default:
		return false;
	}

	switch (ip_proto) {
	case IPPROTO_GRE: {
		struct gre_hdr {
			__be16 flags;
			__be16 proto;
		} *hdr, _hdr;

		hdr = skb_header_pointer(skb, nhoff, sizeof(_hdr), &_hdr);
		if (!hdr)
			return false;
		/*
		 * Only look inside GRE if version zero and no
		 * routing
		 */
		if (!(hdr->flags & (GRE_VERSION|GRE_ROUTING))) {
			proto = hdr->proto;
			nhoff += 4;
			if (hdr->flags & GRE_CSUM)
				nhoff += 4;
			if (hdr->flags & GRE_KEY)
				nhoff += 4;
			if (hdr->flags & GRE_SEQ)
				nhoff += 4;
			goto again;
		}
		break;
	}
	case IPPROTO_IPIP:
		goto again;
	default:
		break;
	}

	flow->ip_proto = ip_proto;
	poff = proto_ports_offset(ip_proto);
	if (poff >= 0) {
		__be32 *ports, _ports;

		nhoff += poff;
		ports = skb_header_pointer(skb, nhoff, sizeof(_ports), &_ports);
		if (ports)
			flow->ports = *ports;
	}

	return true;
}
