/*
 * net/ipv4/tcp_estats.c
 *
 * Implementation of TCP ESTATS MIB (RFC 4898)
 *
 * Authors:
 *   John Heffner <jheffner@psc.edu>
 *   Matt Mathis <mathis@psc.edu>
 *   Jeff Semke <semke@psc.edu>
 *
 * The Web10Gig project.  See http://www.web10gig.org
 *
 * Copyright © 2011, Pittsburgh Supercomputing Center (PSC).
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/bootmem.h>
#include <linux/list.h>
#include <net/tcp_estats.h>
#include <net/tcp.h>
#include <asm/atomic.h>
#include <asm/byteorder.h>

#define ESTATS_INF32	0xffffffff

#define ESTATS_DEATH_SLOTS	8
#define ESTATS_PERSIST_TIME	60

static void death_cleanup(unsigned long dummy);

/* Global stats reader-writer lock */
DEFINE_RWLOCK(tcp_estats_linkage_lock);

/* Data structures for tying together stats */
static int tcp_estats_next_cid = 0x7fffff;
static int tcp_estats_htsize;
int tcp_estats_conn_num;
struct list_head *tcp_estats_ht;
struct list_head *tcp_estats_head;

static struct tcp_estats *death_slots[ESTATS_DEATH_SLOTS];
static int cur_death_slot;
static DEFINE_SPINLOCK(death_lock);
static struct timer_list stats_persist_timer = TIMER_INITIALIZER(death_cleanup, 0, 0);
static int ndeaths;

extern struct proc_dir_entry *proc_tcp_estats_dir;
extern int sysctl_tcp_estats_max_conns;

/*
 * Structural maintainance
 */

static inline int tcp_estats_hash(int cid)
{
	return cid % tcp_estats_htsize;
}

static inline int tcp_estats_hashstep(int cid)
{
	return ((cid + tcp_estats_htsize) & 0x7fffffff);
}

struct tcp_estats *tcp_estats_lookup(int cid)
{
	struct list_head *p, *bucket_head;
	struct tcp_estats *stats;

	bucket_head = &tcp_estats_ht[tcp_estats_hash(cid)];
	list_for_each(p, bucket_head) {
		stats = list_entry(p, struct tcp_estats, estats_hash_list);
		if (stats->estats_cid == cid)
			return stats;
	}
	
	return NULL;
}

static int get_next_cid(void)
{
	u32 i;

	if (tcp_estats_conn_num >= sysctl_tcp_estats_max_conns)
		return -1;

	i = (u32)tcp_estats_next_cid;
	while (tcp_estats_lookup(i)) {
		if ((i = tcp_estats_hashstep(i)) == tcp_estats_next_cid) {
			tcp_estats_next_cid = (tcp_estats_next_cid + 1) & 0x7fffffff;
			i = (u32)tcp_estats_next_cid;
		}
	}
	tcp_estats_next_cid = (tcp_estats_next_cid + 1) & 0x7fffffff;

	return i;
}

static void stats_link(struct tcp_estats *stats)
{
	write_lock_bh(&tcp_estats_linkage_lock);

	if ((stats->estats_cid = get_next_cid()) < 0) {
		write_unlock_bh(&tcp_estats_linkage_lock);
		return;
	}

	list_add(&stats->estats_hash_list,
		&tcp_estats_ht[tcp_estats_hash(stats->estats_cid)]);
	list_add(&stats->estats_list, tcp_estats_head);

	tcp_estats_conn_num++;
	proc_tcp_estats_dir->nlink = tcp_estats_conn_num + 2;

	write_unlock_bh(&tcp_estats_linkage_lock);
}

static void stats_unlink(struct tcp_estats *stats)
{
	write_lock_bh(&tcp_estats_linkage_lock);

	list_del(&stats->estats_hash_list);
	list_del(&stats->estats_list);

	tcp_estats_conn_num--;
	proc_tcp_estats_dir->nlink = tcp_estats_conn_num + 2;

	write_unlock_bh(&tcp_estats_linkage_lock);
}

static void stats_persist(struct tcp_estats *stats)
{
	spin_lock_bh(&death_lock);

	stats->estats_death_next = death_slots[cur_death_slot];
	death_slots[cur_death_slot] = stats;
	if (ndeaths <= 0)
		mod_timer(&stats_persist_timer,
			  jiffies +
			  ESTATS_PERSIST_TIME * HZ / ESTATS_DEATH_SLOTS);
	ndeaths++;

	spin_unlock_bh(&death_lock);
}

static void death_cleanup(unsigned long dummy)
{
	struct tcp_estats *stats, *next;

	if (!spin_trylock_bh(&death_lock)) {
		if (ndeaths > 0)
			mod_timer(&stats_persist_timer, jiffies + HZ);
		return;
	}

	cur_death_slot = (cur_death_slot + 1) % ESTATS_DEATH_SLOTS;
	stats = death_slots[cur_death_slot];
	while (stats) {
		stats->estats_dead = 1;
		ndeaths--;
		next = stats->estats_death_next;
		tcp_estats_unuse(stats);
		stats = next;
	}
	death_slots[cur_death_slot] = NULL;

	if (ndeaths > 0)
		mod_timer(&stats_persist_timer,
			  jiffies +
			  ESTATS_PERSIST_TIME * HZ / ESTATS_DEATH_SLOTS);

	spin_unlock_bh(&death_lock);
}

/* Called whenever a TCP/IPv4 sock is created.
 * net/ipv4/tcp_ipv4.c: tcp_v4_syn_recv_sock,
 *			tcp_v4_init_sock
 * Allocates a stats structure and initializes values.
 */
int __tcp_estats_create(struct sock *sk, enum tcp_estats_addrtype addrtype)
{
	struct tcp_estats *stats;
	struct tcp_estats_directs *vars;
	struct tcp_sock *tp = tcp_sk(sk);

	if (!sysctl_tcp_estats_enabled) {
		tp->tcp_stats = NULL;
		return -1;
	}

	stats = kzalloc(sizeof(struct tcp_estats), gfp_any());
	if (!stats)
		return -ENOMEM;

	tp->tcp_stats = stats;
	vars = &stats->estats_vars;

	stats->estats_cid = -1;
	stats->estats_vars.LocalAddressType = addrtype;

	sock_hold(sk);
	stats->estats_sk = sk;
	atomic_set(&stats->estats_users, 0);

	stats->estats_limstate = TCP_ESTATS_SNDLIM_STARTUP;
	stats->estats_ca_state = TCP_CA_Open;
	stats->estats_start_ts = stats->estats_limstate_ts =
	stats->estats_ca_state_ts = stats->estats_current_ts = ktime_get();
	do_gettimeofday(&stats->estats_start_tv);

	vars->ActiveOpen = !in_interrupt();

	vars->SndMax = tp->snd_nxt;
	vars->SndInitial = tp->snd_nxt;

	vars->MinRTT = vars->MinRTO = vars->MinMSS = vars->MinSsthresh =
	    ESTATS_INF32;

	tcp_estats_use(stats);

	return 0;
}

void __tcp_estats_destroy(struct sock *sk)
{
	struct tcp_estats *stats = tcp_sk(sk)->tcp_stats;

	if (stats == NULL)
		return;

	if (static_branch(&tcp_estats_key)) {
		/* Attribute final sndlim time. */
		tcp_estats_update_sndlim(tcp_sk(stats->estats_sk),
				 stats->estats_limstate);
		tcp_estats_update_ca_state(sk,
				inet_csk(sk)->icsk_ca_state);

		if (stats->estats_cid >= 0)
			stats_persist(stats);
		else
			tcp_estats_unuse(stats);
	} else
		tcp_estats_unuse(stats);
}

/* Do not call directly.  Called from tcp_estats_unuse(). */
void tcp_estats_free(struct tcp_estats *stats)
{
	if (stats->estats_cid >= 0) {
		stats_unlink(stats);
	}
	sock_put(stats->estats_sk);
	kfree(stats);
}

/* Called when a connection enters the ESTABLISHED state, and has all its
 * state initialized.
 * net/ipv4/tcp_input.c: tcp_rcv_state_process,
 *			 tcp_rcv_synsent_state_process
 * Here we link the statistics structure in so it is visible in the /proc
 * fs, and do some final init.
 */
void __tcp_estats_establish(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_estats *stats = tp->tcp_stats;
	struct tcp_estats_directs *vars = &stats->estats_vars;

	if (stats == NULL)
		return;

	/* Let's set these here, since they can't change once the
	 * connection is established.
	 */
	vars->LocalPort = inet->num;
	vars->RemPort = ntohs(inet->dport);

	if (vars->LocalAddressType == TCP_ESTATS_ADDRTYPE_IPV4) {
		memcpy(&vars->LocalAddress, &inet->rcv_saddr, 4);
		memcpy(&vars->RemAddress, &inet->daddr, 4);
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (vars->LocalAddressType == TCP_ESTATS_ADDRTYPE_IPV6) {
		memcpy(&vars->LocalAddress, &(inet6_sk(sk)->saddr), 16);
		memcpy(&vars->RemAddress, &(inet6_sk(sk)->daddr), 16);
	}
#endif
	else {
		printk(KERN_ERR "TCP ESTATS: LocalAddressType not valid.\n");
	}
	((char *)&vars->LocalAddress)[16] = ((char *)&vars->RemAddress)[16] =
	    vars->LocalAddressType;

	tcp_estats_update_finish_segrecv(tp);
	tcp_estats_update_rwin_rcvd(tp);
	tcp_estats_update_rwin_sent(tp);

	vars->MaxRetranThresh = tp->reordering;
	vars->RecInitial = tp->rcv_nxt;

	vars->InitCwnd = tp->snd_cwnd;
	vars->InitCwndClamp = tp->snd_cwnd_clamp;
	vars->InitSsthresh = tp->snd_ssthresh;
	vars->InitReordering = tp->reordering;
	vars->InitSRTT = tp->srtt;
	vars->InitRTTVar = tp->rttvar;


	stats_link(stats);

	tcp_estats_update_sndlim(tp, TCP_ESTATS_SNDLIM_SENDER);
}

/*
 * Statistics update functions
 */

void tcp_estats_update_snd_nxt(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;

	if (after(tp->snd_nxt, stats->estats_vars.SndMax))
		stats->estats_vars.SndMax = tp->snd_nxt;
}

void tcp_estats_update_acked(struct tcp_sock *tp, u32 ack)
{
	struct tcp_estats *stats = tp->tcp_stats;

	stats->estats_vars.ThruOctetsAcked += ack - tp->snd_una;
}

void tcp_estats_update_rtt(struct sock *sk, unsigned long rtt_sample)
{
	struct tcp_estats *stats = tcp_sk(sk)->tcp_stats;
	unsigned long rtt_sample_msec = rtt_sample * 1000 / HZ;
	u32 rto;

	stats->estats_vars.SampleRTT = rtt_sample_msec;

	if (rtt_sample_msec > stats->estats_vars.MaxRTT)
		stats->estats_vars.MaxRTT = rtt_sample_msec;
	if (rtt_sample_msec < stats->estats_vars.MinRTT)
		stats->estats_vars.MinRTT = rtt_sample_msec;

	stats->estats_vars.CountRTT++;
	stats->estats_vars.SumRTT += rtt_sample_msec;

	rto = inet_csk(sk)->icsk_rto * 1000 / HZ;
	if (rto > stats->estats_vars.MaxRTO)
		stats->estats_vars.MaxRTO = rto;
	if (rto < stats->estats_vars.MinRTO)
		stats->estats_vars.MinRTO = rto;
}

void tcp_estats_update_timeout(struct sock *sk)
{
	struct tcp_estats *stats = tcp_sk(sk)->tcp_stats;

	if (inet_csk(sk)->icsk_backoff)
		stats->estats_vars.SubsequentTimeouts++;
	else
		stats->estats_vars.Timeouts++;
	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Open)
		stats->estats_vars.AbruptTimeouts++;
}

void tcp_estats_update_mss(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	int mss = tp->mss_cache;

	if (mss > stats->estats_vars.MaxMSS)
		stats->estats_vars.MaxMSS = mss;
	if (mss < stats->estats_vars.MinMSS)
		stats->estats_vars.MinMSS = mss;
}

void tcp_estats_update_finish_segrecv(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	struct tcp_estats_directs *vars = &stats->estats_vars;
	u32 mss = tp->mss_cache;
	u32 cwnd;
	u32 ssthresh;
	u32 pipe_size;

	stats->estats_current_ts = ktime_get();

	cwnd = tp->snd_cwnd * mss;
	if (tp->snd_cwnd <= tp->snd_ssthresh) {
		if (cwnd > vars->MaxSsCwnd)
			vars->MaxSsCwnd = cwnd;
	} else {
		if (cwnd > vars->MaxCaCwnd)
			vars->MaxCaCwnd = cwnd;
	}

	pipe_size = tcp_packets_in_flight(tp) * mss;
	if (pipe_size > vars->MaxPipeSize)
		vars->MaxPipeSize = pipe_size;

	/* Discard initiail ssthresh set at infinity. */
	if (tp->snd_ssthresh >= 0x7ffffff) {
		return;
	}
	ssthresh = tp->snd_ssthresh * tp->mss_cache;
	if (ssthresh > vars->MaxSsthresh)
		vars->MaxSsthresh = ssthresh;
	if (ssthresh < vars->MinSsthresh)
		vars->MinSsthresh = ssthresh;
}

void tcp_estats_update_rwin_rcvd(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	u32 win = tp->snd_wnd;

	if (win > stats->estats_vars.MaxRwinRcvd)
		stats->estats_vars.MaxRwinRcvd = win;
	if (win == 0)
		stats->estats_vars.ZeroRwinRcvd++;
}

void tcp_estats_update_rwin_sent(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	u32 win = tp->rcv_wnd;

	if (win > stats->estats_vars.MaxRwinSent)
		stats->estats_vars.MaxRwinSent = win;
	if (win == 0)
		stats->estats_vars.ZeroRwinSent++;
}

void tcp_estats_update_sndlim(struct tcp_sock *tp, int why)
{
	struct tcp_estats *stats = tp->tcp_stats;
	ktime_t now;

	if (why < 0) {
		printk(KERN_ERR "tcp_estats_update_sndlim: BUG: why < 0\n");
		return;
	}

	now = ktime_get();
	stats->estats_vars.snd_lim_time[stats->estats_limstate]
	    += ktime_to_ns(ktime_sub(now, stats->estats_limstate_ts));

	stats->estats_limstate_ts = now;
	if (stats->estats_limstate != why) {
		stats->estats_limstate = why;
		stats->estats_vars.snd_lim_trans[why]++;
	}
}

void tcp_estats_update_congestion(struct tcp_sock *tp, int offset)
{
	struct tcp_estats *stats = tp->tcp_stats;

	stats->estats_vars.CongSignals++;
	stats->estats_vars.CongSignalsArray[offset]++;
	stats->estats_vars.PreCongSumCwnd += tp->snd_cwnd * tp->mss_cache;
	stats->estats_vars.PreCongSumRTT += stats->estats_vars.SampleRTT;
}

void tcp_estats_update_post_congestion(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	
	stats->estats_vars.PostCongCountRTT++;
	stats->estats_vars.PostCongSumRTT += stats->estats_vars.SampleRTT;
}

void tcp_estats_update_segsend(struct sock *sk, int len, int pcount,
			       u32 seq, u32 end_seq, int flags)
{
	struct tcp_estats *stats = tcp_sk(sk)->tcp_stats;

	stats->estats_current_ts = ktime_get();

	/* We know we're sending a segment. */
	stats->estats_vars.SegsOut += pcount;

	/* A pure ACK contains no data; everything else is data. */
	if (len > 0) {
		stats->estats_vars.DataSegsOut += pcount;
		stats->estats_vars.DataOctetsOut += len;
	}

	/* Check for retransmission. */
	if (flags & TCPCB_FLAG_SYN) {
		if (inet_csk(sk)->icsk_retransmits)
			stats->estats_vars.SegsRetrans++;
	} else if (before(seq, stats->estats_vars.SndMax)) {
		stats->estats_vars.SegsRetrans += pcount;
		stats->estats_vars.OctetsRetrans += end_seq - seq;
	}
}

void tcp_estats_update_segrecv(struct tcp_sock *tp, struct sk_buff *skb)
{
	struct tcp_estats_directs *vars = &tp->tcp_stats->estats_vars;
	struct tcphdr *th = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);

	vars->SegsIn++;
	if (skb->len == th->doff * 4) {
		if (TCP_SKB_CB(skb)->ack_seq == tp->snd_una)
			vars->DupAcksIn++;
	} else {
		vars->DataSegsIn++;
		vars->DataOctetsIn += skb->len - th->doff * 4;
	}

	vars->IpTtl = iph->ttl;
	vars->IpTosIn = iph->tos;
}

void tcp_estats_update_rcvd(struct tcp_sock *tp, u32 seq)
{
	struct tcp_estats *stats = tp->tcp_stats;

	stats->estats_vars.ThruOctetsReceived += seq - tp->rcv_nxt;
}

void tcp_estats_update_writeq(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_estats_directs *vars = &tp->tcp_stats->estats_vars;
	int len = tp->write_seq - vars->SndMax;

	if (len > vars->MaxAppWQueue)
		vars->MaxAppWQueue = len;
}

static inline u32 ofo_qlen(struct tcp_sock *tp)
{
	if (!skb_peek(&tp->out_of_order_queue))
		return 0;
	else
		return TCP_SKB_CB(tp->out_of_order_queue.prev)->end_seq -
		    TCP_SKB_CB(tp->out_of_order_queue.next)->seq;
}

void tcp_estats_update_recvq(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_estats_directs *vars = &tp->tcp_stats->estats_vars;
	u32 len1 = tp->rcv_nxt - tp->copied_seq;
	u32 len2 = ofo_qlen(tp);

	if (vars->MaxAppRQueue < len1)
		vars->MaxAppRQueue = len1;

	if (vars->MaxReasmQueue < len2)
		vars->MaxReasmQueue = len2;
}

void tcp_estats_update_reordering(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;

	if (tp->reordering > stats->estats_vars.MaxRetranThresh)
		stats->estats_vars.MaxRetranThresh = tp->reordering;
}

void tcp_estats_update_ca_state(struct sock *sk, int state)
{
	struct tcp_estats *stats = tcp_sk(sk)->tcp_stats;
	ktime_t now;

	now = ktime_get();
	stats->estats_vars.ca_state_time[stats->estats_ca_state]
	    += ktime_to_ns(ktime_sub(now, stats->estats_ca_state_ts));

	stats->estats_ca_state_ts = now;
	if (stats->estats_ca_state != state) {
		stats->estats_ca_state = state;
		stats->estats_vars.ca_state_trans[state]++;
	}
}

/*
 * Read/write functions
 */
/* A read handler for reading directly from the stats structure */
static void read_stats(void *buf, struct tcp_estats *stats,
		       struct tcp_estats_var *vp)
{
	memcpy(buf, (char *)stats + vp->read_data, tcp_estats_var_len(vp));
}

static void read_LimCwnd(void *buf, struct tcp_estats *stats,
			 struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 tmp = (u32) (tp->snd_cwnd_clamp * tp->mss_cache);

	memcpy(buf, &tmp, 4);
}

static void write_LimCwnd(void *buf, struct tcp_estats *stats,
			  struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);

	tp->snd_cwnd_clamp = min(*(u32 *) buf / tp->mss_cache, 65535U);
}

static void read_LimSsthresh(void *buf, struct tcp_estats *stats,
			     struct tcp_estats_var *vp)
{
	u32 tmp = (u32) sysctl_tcp_max_ssthresh;

	if (tmp == 0)
		tmp = 0x7fffffff;
	memcpy(buf, &sysctl_tcp_max_ssthresh, 4);
}

static void write_LimRwin(void *buf, struct tcp_estats *stats,
			  struct tcp_estats_var *vp)
{
	u32 val;
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);

	memcpy(&val, buf, 4);
	tp->window_clamp = min(val, 65535U << tp->rx_opt.rcv_wscale);
}

static void write_Sndbuf(void *buf, struct tcp_estats *stats,
			 struct tcp_estats_var *vp)
{
	int val;
	struct sock *sk = stats->estats_sk;

	memcpy(&val, buf, sizeof(int));

	sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
	sk->sk_sndbuf =
	    max_t(int, SOCK_MIN_SNDBUF, min_t(int, sysctl_wmem_max, val));
	sk->sk_write_space(sk);
}

static void write_Rcvbuf(void *buf, struct tcp_estats *stats,
			 struct tcp_estats_var *vp)
{
	int val;
	struct sock *sk = stats->estats_sk;

	memcpy(&val, buf, sizeof(int));

	sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
	sk->sk_rcvbuf =
	    max_t(int, SOCK_MIN_RCVBUF, min_t(int, sysctl_rmem_max, val));
}

static void read_State(void *buf, struct tcp_estats *stats,
		       struct tcp_estats_var *vp)
{
	/* A mapping from Linux to MIB state. */
	static char state_map[] = { 0, TCP_ESTATS_STATE_ESTABLISHED,
				    TCP_ESTATS_STATE_SYNSENT,
				    TCP_ESTATS_STATE_SYNRECEIVED,
				    TCP_ESTATS_STATE_FINWAIT1,
				    TCP_ESTATS_STATE_FINWAIT2,
				    TCP_ESTATS_STATE_TIMEWAIT,
				    TCP_ESTATS_STATE_CLOSED,
				    TCP_ESTATS_STATE_CLOSEWAIT,
				    TCP_ESTATS_STATE_LASTACK,
				    TCP_ESTATS_STATE_LISTEN,
				    TCP_ESTATS_STATE_CLOSING };
	s32 val = state_map[stats->estats_sk->sk_state];
	
	memcpy(buf, &val, sizeof(val));
}

static void write_State(void *buf, struct tcp_estats *stats,
			struct tcp_estats_var *vp)
{
	int val;
	struct sock *sk = stats->estats_sk;

	memcpy(&val, buf, sizeof(int));
	if (val != 12)		/* deleteTCB, RFC 2012 */
		return;
	sk->sk_prot->disconnect(sk, 0);
}

/* A read handler for reading directly from the sk for 32-bit types only! */
static void read_sk32(void *buf, struct tcp_estats *stats,
		      struct tcp_estats_var *vp)
{
	memcpy(buf, (char *)(stats->estats_sk) + vp->read_data, 4);
}

static void write_LimMSS(void *buf, struct tcp_estats *stats,
			 struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val = *(u32 *) buf;

	if (val >= (1 << 16))
		val = (1 << 16) - 1;
	if (val < 1)
		val = 1;

	tp->rx_opt.mss_clamp =
	    min_t(u16, val, min(tp->rx_opt.rec_mss, tp->rx_opt.user_mss));
	if (tp->mss_cache > tp->rx_opt.mss_clamp)
		tp->mss_cache = tp->rx_opt.mss_clamp;

	tcp_estats_update_mss(tp);
}

static void read_ElapsedSecs(void *buf, struct tcp_estats *stats,
			     struct tcp_estats_var *vp)
{
	ktime_t elapsed = ktime_sub(stats->estats_current_ts,
				    stats->estats_start_ts);
	u32 secs = ktime_to_timeval(elapsed).tv_sec;

	memcpy(buf, &secs, 4);
}

static void read_ElapsedMicroSecs(void *buf, struct tcp_estats *stats,
				  struct tcp_estats_var *vp)
{
	ktime_t elapsed = ktime_sub(stats->estats_current_ts,
				    stats->estats_start_ts);
	u32 usecs = ktime_to_timeval(elapsed).tv_usec;

	memcpy(buf, &usecs, 4);
}

static void read_StartTimeSecs(void *buf, struct tcp_estats *stats,
			       struct tcp_estats_var *vp)
{
	u32 secs = (u32) stats->estats_start_tv.tv_sec;

	memcpy(buf, &secs, 4);
}

static void read_StartTimeMicroSecs(void *buf, struct tcp_estats *stats,
				    struct tcp_estats_var *vp)
{
	u32 usecs = (u32) stats->estats_start_tv.tv_usec;

	memcpy(buf, &usecs, 4);
}

static void read_RetranThresh(void *buf, struct tcp_estats *stats,
			      struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = tp->reordering;
	memcpy(buf, &val, 4);
}

static void read_PipeSize(void *buf, struct tcp_estats *stats,
			  struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = tcp_packets_in_flight(tp) * tp->mss_cache;
	memcpy(buf, &val, 4);
}

static void read_SmoothedRTT(void *buf, struct tcp_estats *stats,
			     struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;
	
	val = (tp->srtt >> 3) * 1000 / HZ;
	memcpy(buf, &val, 4);
}

static void read_CurRTO(void *buf, struct tcp_estats *stats,
			struct tcp_estats_var *vp)
{
	struct inet_connection_sock *icsk = inet_csk(stats->estats_sk);
	u32 val;

	val = icsk->icsk_rto * 1000 / HZ;
	memcpy(buf, &val, 4);
}

static void read_RTTVar(void *buf, struct tcp_estats *stats,
			struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = (tp->rttvar >> 2) * 1000 / HZ;
	memcpy(buf, &val, 4);
}

static void read_RcvRTT(void *buf, struct tcp_estats *stats,
			struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;
	
	val = ((1000000*tp->rcv_rtt_est.rtt)/HZ)>>3;
	memcpy(buf, &val, 4);
}

static void read_CurCwnd(void *buf, struct tcp_estats *stats,
			 struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = tp->snd_cwnd * tp->mss_cache;
	memcpy(buf, &val, 4);
}

static void read_CurSsthresh(void *buf, struct tcp_estats *stats,
			     struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = tp->snd_ssthresh == 0x7fffffff ?
	      tp->snd_ssthresh * tp->mss_cache : 0xffffffff;
	memcpy(buf, &val, 4);
}

/* Note: this value returned is technically incorrect between a
 * setsockopt of IP_TOS, and when the next segment is sent. */
static void read_IpTosOut(void *buf, struct tcp_estats *stats,
			  struct tcp_estats_var *vp)
{
	struct inet_sock *inet = inet_sk(stats->estats_sk);

	*(char *)buf = inet->tos;
}

static void read_InRecovery(void *buf, struct tcp_estats *stats,
			    struct tcp_estats_var *vp)
{
	struct inet_connection_sock *icsk = inet_csk(stats->estats_sk);
	s32 val;

	val = icsk->icsk_ca_state > TCP_CA_CWR ? 1 : 2;
	memcpy(buf, &val, 4);
}

static void read_CurTimeoutCount(void *buf, struct tcp_estats *stats,
				 struct tcp_estats_var *vp)
{
	struct inet_connection_sock *icsk = inet_csk(stats->estats_sk);
	u32 val;
	
	val = icsk->icsk_retransmits;
	memcpy(buf, &val, 4);
}

/* Note: all these (Nagle, SACK, ECN, TimeStamps) are incorrect
 * if the sysctl values are changed during the connection. */
static void read_Nagle(void *buf, struct tcp_estats *stats,
		       struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	s32 val;

	val = tp->nonagle ? 2 : 1;
	memcpy(buf, &val, 4);
}

static void read_WillSendSACK(void *buf, struct tcp_estats *stats,
			      struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	s32 val;

	if (tp->rx_opt.sack_ok)
		val = 1;
	else
		val = sysctl_tcp_sack ? 3 : 2;
	memcpy(buf, &val, 4);
}

#define read_WillUseSACK	read_WillSendSACK

static void read_ECN(void *buf, struct tcp_estats *stats,
		     struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	s32 val;

	if (tp->ecn_flags & TCP_ECN_OK)
		val = 1;
	else
		val = sysctl_tcp_ecn ? 3 : 2;
	memcpy(buf, &val, 4);
}

static void read_TimeStamps(void *buf, struct tcp_estats *stats,
			    struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	s32 val;

	if (tp->rx_opt.tstamp_ok)
		val = 1;
	else
		val = sysctl_tcp_timestamps ? 3 : 2;
	memcpy(buf, &val, 4);
}

static void read_MSSSent(void *buf, struct tcp_estats *stats,
			 struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = tp->advmss;
	memcpy(buf, &val, 4);
}

static void read_MSSRcvd(void *buf, struct tcp_estats *stats,
			 struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = tp->rx_opt.rec_mss;
	memcpy(buf, &val, 4);
}

/* Note: WinScaleSent and WinScaleRcvd are incorrectly
 * implemented for the case where we sent a scale option
 * but did not receive one. */
static void read_WinScaleSent(void *buf, struct tcp_estats *stats,
			      struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	s32 val;

	val = tp->rx_opt.wscale_ok ? tp->rx_opt.rcv_wscale : -1;
	memcpy(buf, &val, 4);
}

static void read_WinScaleRcvd(void *buf, struct tcp_estats *stats,
			      struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	s32 val;

	val = tp->rx_opt.wscale_ok ? tp->rx_opt.snd_wscale : -1;
	memcpy(buf, &val, 4);
}

static void read_CurAppWQueue(void *buf, struct tcp_estats *stats,
			      struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val = tp->write_seq - stats->estats_vars.SndMax;

	memcpy(buf, &val, 4);
}

static void read_CurAppRQueue(void *buf, struct tcp_estats *stats,
			      struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val = tp->rcv_nxt - tp->copied_seq;

	memcpy(buf, &val, 4);
}

static void read_CurReasmQueue(void *buf, struct tcp_estats *stats,
			       struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val = ofo_qlen(tp);

	memcpy(buf, &val, 4);
}

/*
 * Table of exported MIB variables
 */
#define OFFSET_IN(type,var)	((unsigned long)(&(((type *)NULL)->var)))
#define OFFSET_ST(field)	((unsigned long)(&(((struct tcp_estats *)NULL)->estats_vars.field)))
#define OFFSET_SK(field)	((unsigned long)(&(((struct sock *)NULL)->field)))
#define OFFSET_TP(field)	((unsigned long)(&(((struct tcp_sock *)NULL)->field)))
#define STATSVAR(__name,__type)		{ .name = #__name, .type = TCP_ESTATS_TYPE_##__type, .read = read_stats, .read_data = OFFSET_ST(__name), .write = NULL }
#define STATSVARN(__name,__type,__var)	{ .name = #__name, .type = TCP_ESTATS_TYPE_##__type, .read = read_stats, .read_data = OFFSET_ST(__var), .write = NULL }
#define TPVAR32(__name,__type,__var)	{ .name = #__name, .type = TCP_ESTATS_TYPE_##__type, .read = read_sk32, .read_data = OFFSET_TP(__var), .write = NULL }
#define READFUN(__name,__type)		{ .name = #__name, .type = TCP_ESTATS_TYPE_##__type, .read = read_##__name, .write = NULL }
#define RWFUN(__name,__type)		{ .name = #__name, .type = TCP_ESTATS_TYPE_##__type, .read = read_##__name, .write = write_##__name }

struct tcp_estats_var tcp_estats_var_table[] = {
	/* Connection table */
	STATSVAR(LocalAddressType, INTEGER),
	STATSVAR(LocalAddress, INET_ADDRESS),
	STATSVAR(LocalPort, INET_PORT_NUMBER),
	STATSVARN(RemAddressType, INTEGER, LocalAddressType),
	STATSVAR(RemAddress, INET_ADDRESS),
	STATSVAR(RemPort, INET_PORT_NUMBER),

	/* Perf table */
	STATSVAR(SegsOut, COUNTER32),
	STATSVAR(DataSegsOut, COUNTER32),
	STATSVAR(DataOctetsOut, COUNTER64),
	STATSVAR(SegsRetrans, COUNTER32),
	STATSVAR(OctetsRetrans, COUNTER32),
	STATSVAR(SegsIn, COUNTER32),
	STATSVAR(DataSegsIn, COUNTER32),
	STATSVAR(DataOctetsIn, COUNTER64),
	READFUN(ElapsedSecs, COUNTER32),
	READFUN(ElapsedMicroSecs, COUNTER32),
	/* StartTimeStamp - Not implemented.
	 * See StartTimeSecs and StartTimeMicroSecs below. */
	TPVAR32(CurMSS, GAUGE32, mss_cache),
	READFUN(PipeSize, GAUGE32),
	STATSVAR(MaxPipeSize, GAUGE32),
	READFUN(SmoothedRTT, GAUGE32),
	READFUN(CurRTO, GAUGE32),
	STATSVAR(CongSignals, COUNTER32),
	STATSVARN(CongSignalsCWR, COUNTER32, CongSignalsArray[CongCWR]),
	STATSVARN(CongSignalsLoss, COUNTER32, CongSignalsArray[CongLoss]),
	STATSVARN(CongSignalsFastRtx, COUNTER32, CongSignalsArray[CongFastRtx]),
	STATSVARN(CongSignalsFRTO, COUNTER32, CongSignalsArray[CongFRTO]),
	STATSVARN(CongSignalsFRTOLoss, COUNTER32, CongSignalsArray[CongFRTOLoss]),
	READFUN(CurCwnd, GAUGE32),
	READFUN(CurSsthresh, GAUGE32),
	STATSVAR(Timeouts, COUNTER32),
	TPVAR32(CurRwinSent, GAUGE32, rcv_wnd),
	STATSVAR(MaxRwinSent, GAUGE32),
	STATSVAR(ZeroRwinSent, GAUGE32),
	TPVAR32(CurRwinRcvd, GAUGE32, snd_wnd),
	STATSVAR(MaxRwinRcvd, GAUGE32),
	STATSVAR(ZeroRwinRcvd, GAUGE32),
	STATSVARN(SndLimTransRwin, COUNTER32,
		  snd_lim_trans[TCP_ESTATS_SNDLIM_RWIN]),
	STATSVARN(SndLimTransCwnd, COUNTER32,
		  snd_lim_trans[TCP_ESTATS_SNDLIM_CWND]),
	STATSVARN(SndLimTransSnd, COUNTER32,
		  snd_lim_trans[TCP_ESTATS_SNDLIM_SENDER]),
	STATSVARN(SndLimTransNagle, COUNTER32,
		  snd_lim_trans[TCP_ESTATS_SNDLIM_NAGLE]),
	STATSVARN(SndLimTransPushone, COUNTER32,
		  snd_lim_trans[TCP_ESTATS_SNDLIM_PUSHONE]),
	STATSVARN(SndLimTransTso, COUNTER32,
		  snd_lim_trans[TCP_ESTATS_SNDLIM_TSO]),
	STATSVARN(SndLimTransFrag, COUNTER32,
		  snd_lim_trans[TCP_ESTATS_SNDLIM_FRAG]),

	STATSVARN(SndLimTimeRwin, COUNTER32,
		  snd_lim_time[TCP_ESTATS_SNDLIM_RWIN]),
	STATSVARN(SndLimTimeCwnd, COUNTER32,
		  snd_lim_time[TCP_ESTATS_SNDLIM_CWND]),
	STATSVARN(SndLimTimeSnd, COUNTER32,
		  snd_lim_time[TCP_ESTATS_SNDLIM_SENDER]),
	STATSVARN(SndLimTimeNagle, COUNTER32,
		  snd_lim_time[TCP_ESTATS_SNDLIM_NAGLE]),
	STATSVARN(SndLimTimePushone, COUNTER32,
		  snd_lim_time[TCP_ESTATS_SNDLIM_PUSHONE]),
	STATSVARN(SndLimTimeTso, COUNTER32,
		  snd_lim_time[TCP_ESTATS_SNDLIM_TSO]),
	STATSVARN(SndLimTimeFrag, COUNTER32,
		  snd_lim_time[TCP_ESTATS_SNDLIM_FRAG]),

	STATSVARN(CAStateOpen, COUNTER32,
		  ca_state_trans[TCP_CA_Open]),
	STATSVARN(CAStateDisorder, COUNTER32,
		  ca_state_trans[TCP_CA_Disorder]),
	STATSVARN(CAStateRecovery, COUNTER32,
		  ca_state_trans[TCP_CA_Recovery]),
	STATSVARN(CAStateCWR, COUNTER32,
		  ca_state_trans[TCP_CA_CWR]),
	STATSVARN(CAStateLoss, COUNTER32,
		  ca_state_trans[TCP_CA_Loss]),

	STATSVARN(CATimeOpen, COUNTER32,
		  ca_state_time[TCP_CA_Open]),
	STATSVARN(CATimeDisorder, COUNTER32,
		  ca_state_time[TCP_CA_Disorder]),
	STATSVARN(CATimeRecovery, COUNTER32,
		  ca_state_time[TCP_CA_Recovery]),
	STATSVARN(CATimeCWR, COUNTER32,
		  ca_state_time[TCP_CA_CWR]),
	STATSVARN(CATimeLoss, COUNTER32,
		  ca_state_time[TCP_CA_Loss]),

	STATSVAR(SendStall, COUNTER32),

	/* Path table */
	READFUN(RetranThresh, GAUGE32),
	STATSVAR(MaxRetranThresh, COUNTER32),
	STATSVAR(NonRecovDAEpisodes, COUNTER32),
	STATSVAR(SumOctetsReordered, COUNTER32),
	STATSVAR(NonRecovDA, COUNTER32),
	STATSVAR(SampleRTT, GAUGE32),
	READFUN(RTTVar, GAUGE32),
	STATSVAR(MaxRTT, GAUGE32),
	STATSVAR(MinRTT, GAUGE32),
	STATSVAR(SumRTT, COUNTER64),
	STATSVAR(CountRTT, COUNTER32),
	STATSVAR(MaxRTO, GAUGE32),
	STATSVAR(MinRTO, GAUGE32),
	STATSVAR(IpTtl, OCTET),
	STATSVAR(IpTosIn, OCTET),
	READFUN(IpTosOut, OCTET),
	STATSVAR(PreCongSumCwnd, COUNTER32),
	STATSVAR(PreCongSumRTT, COUNTER32),
	STATSVAR(PostCongSumRTT, COUNTER32),
	STATSVAR(PostCongCountRTT, COUNTER32),
	STATSVAR(ECNsignals, COUNTER32),
	STATSVAR(DupAckEpisodes, COUNTER32),
	READFUN(RcvRTT, GAUGE32),
	STATSVAR(DupAcksOut, COUNTER32),
	STATSVAR(CERcvd, COUNTER32),
	STATSVAR(ECESent, COUNTER32),

	/* Stack table */
	STATSVAR(ActiveOpen, INTEGER),
	READFUN(MSSSent, UNSIGNED32),
	READFUN(MSSRcvd, UNSIGNED32),
	READFUN(WinScaleSent, INTEGER32),
	READFUN(WinScaleRcvd, INTEGER32),
	READFUN(TimeStamps, INTEGER),
	READFUN(ECN, INTEGER),
	READFUN(WillSendSACK, INTEGER),
	READFUN(WillUseSACK, INTEGER),
	RWFUN(State, INTEGER),
	READFUN(Nagle, INTEGER),
	STATSVAR(MaxSsCwnd, GAUGE32),
	STATSVAR(MaxCaCwnd, GAUGE32),
	STATSVAR(MaxSsthresh, GAUGE32),
	STATSVAR(MinSsthresh, GAUGE32),
	READFUN(InRecovery, INTEGER),
	STATSVAR(DupAcksIn, COUNTER32),
	STATSVAR(SpuriousFrDetected, COUNTER32),
	STATSVAR(SpuriousRtoDetected, COUNTER32),
	STATSVAR(SoftErrors, COUNTER32),
	STATSVARN(SoftErrorReasonBelowDataWindow, COUNTER32,
		 SoftErrorReason[belowDataWindow]),
	STATSVARN(SoftErrorReasonAboveDataWindow, COUNTER32,
		 SoftErrorReason[aboveDataWindow]),
	STATSVARN(SoftErrorReasonBelowAckWindow, COUNTER32,
		 SoftErrorReason[belowAckWindow]),
	STATSVARN(SoftErrorReasonAboveAckWindow, COUNTER32,
		 SoftErrorReason[aboveAckWindow]),
	STATSVARN(SoftErrorReasonBelowTSWindow, COUNTER32,
		 SoftErrorReason[belowTSWindow]),
	STATSVARN(SoftErrorReasonAboveTSWindow, COUNTER32,
		 SoftErrorReason[aboveTSWindow]),
	STATSVARN(SoftErrorReasonDataCheckSum, COUNTER32,
		 SoftErrorReason[dataCheckSum]),
	STATSVARN(SoftErrorReasonOtherSoftError, COUNTER32,
		 SoftErrorReason[otherSoftError]),

	STATSVAR(SlowStart, COUNTER32),
	STATSVAR(CongAvoid, COUNTER32),
	STATSVAR(OtherReductions, COUNTER32),
	STATSVAR(CongOverCount, COUNTER32),
	STATSVAR(FastRetran, COUNTER32),
	STATSVAR(SubsequentTimeouts, COUNTER32),
	READFUN(CurTimeoutCount, GAUGE32),
	STATSVAR(AbruptTimeouts, COUNTER32),
	STATSVAR(SACKsRcvd, COUNTER32),
	STATSVAR(SACKBlocksRcvd, COUNTER32),
	STATSVAR(DSACKDups, COUNTER32),
	STATSVAR(MaxMSS, GAUGE32),
	STATSVAR(MinMSS, GAUGE32),
	STATSVAR(SndInitial, UNSIGNED32),
	STATSVAR(RecInitial, UNSIGNED32),
	STATSVAR(CurRetxQueue, GAUGE32),
	STATSVAR(MaxRetxQueue, GAUGE32),
	READFUN(CurReasmQueue, GAUGE32),
	STATSVAR(MaxReasmQueue, GAUGE32),

	/* App table */
	TPVAR32(SndUna, COUNTER32, snd_una),
	TPVAR32(SndNxt, UNSIGNED32, snd_nxt),
	STATSVAR(SndMax, COUNTER32),
	STATSVAR(ThruOctetsAcked, COUNTER64),
	TPVAR32(RcvNxt, COUNTER32, rcv_nxt),
	STATSVAR(ThruOctetsReceived, COUNTER64),
	READFUN(CurAppWQueue, GAUGE32),
	STATSVAR(MaxAppWQueue, GAUGE32),
	READFUN(CurAppRQueue, GAUGE32),
	STATSVAR(MaxAppRQueue, GAUGE32),

	/* Tune table */
	RWFUN(LimCwnd, GAUGE32),
	/* We can't write LimSsthresh for now because it is only a
	 * a sysctl.  Maybe add per-connection variable later. */
	READFUN(LimSsthresh, GAUGE32),
	{
	 .name = "LimRwin",
	 .type = TCP_ESTATS_TYPE_GAUGE32,
	 .read = read_sk32,
	 .read_data = OFFSET_TP(window_clamp),
	 .write = write_LimRwin,
	 },
	{
	 .name = "LimMSS",
	 .type = TCP_ESTATS_TYPE_GAUGE32,
	 .read = read_sk32,
	 .read_data = OFFSET_TP(rx_opt.mss_clamp),
	 .write = write_LimMSS,
	 },

	/* Extras (non-standard) */
	STATSVAR(OtherReductionsCV, COUNTER32),
	STATSVAR(OtherReductionsCM, COUNTER32),
	READFUN(StartTimeSecs, UNSIGNED32),
	READFUN(StartTimeMicroSecs, UNSIGNED32),
	{
	 .name = "Sndbuf",
	 .type = TCP_ESTATS_TYPE_GAUGE32,
	 .read = read_sk32,
	 .read_data = OFFSET_SK(sk_sndbuf),
	 .write = write_Sndbuf,
	 },
	{
	 .name = "Rcvbuf",
	 .type = TCP_ESTATS_TYPE_GAUGE32,
	 .read = read_sk32,
	 .read_data = OFFSET_SK(sk_rcvbuf),
	 .write = write_Rcvbuf,
	 },

	STATSVAR(InitCwnd, COUNTER32),
	STATSVAR(InitCwndClamp, COUNTER32),
	STATSVAR(InitSsthresh, COUNTER32),
	STATSVAR(InitReordering, COUNTER32),
	STATSVAR(InitSRTT, COUNTER32),
	STATSVAR(InitRTTVar, COUNTER32),

	{.name = NULL}
};

void __init tcp_estats_init()
{
	int order;
	int i;

	tcp_estats_ht =
	    (struct list_head *)alloc_large_system_hash("TCP ESTATS",
							sizeof (struct list_head),
							tcp_hashinfo.ehash_size,
							(totalram_pages >= 128 * 1024) ?
							13 : 15,
							0,
							&order, NULL,
							64 * 1024);
	tcp_estats_htsize = 1 << order;
	for (i = 0; i < tcp_estats_htsize; i++)
		INIT_LIST_HEAD(&tcp_estats_ht[i]);

	if ((tcp_estats_head = kmalloc(sizeof (struct list_head), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR "tcp_estats_init(): kmalloc failed\n");
		goto cleanup_fail;
	}
	INIT_LIST_HEAD(tcp_estats_head);

	if (tcp_estats_proc_init())
		goto cleanup_fail;

	return;

      cleanup_fail:
	free_pages((unsigned long)tcp_estats_ht, order);
	printk("TCP ESTATS: initialization failed.\n");
}

#ifdef CONFIG_IPV6_MODULE
EXPORT_SYMBOL(__tcp_estats_create);
EXPORT_SYMBOL(tcp_estats_update_segrecv);
EXPORT_SYMBOL(tcp_estats_update_finish_segrecv);
#endif
