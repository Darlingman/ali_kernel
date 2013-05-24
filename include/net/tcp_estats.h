/*
 * include/net/tcp_estats.h
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

#ifndef _TCP_ESTATS_H
#define _TCP_ESTATS_H

#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/spinlock.h>

enum tcp_estats_sndlim_states {
	TCP_ESTATS_SNDLIM_NONE = -1,
	TCP_ESTATS_SNDLIM_SENDER,
	TCP_ESTATS_SNDLIM_CWND,
	TCP_ESTATS_SNDLIM_RWIN,
	TCP_ESTATS_SNDLIM_STARTUP,
	TCP_ESTATS_SNDLIM_NAGLE,
	TCP_ESTATS_SNDLIM_PUSHONE,
	TCP_ESTATS_SNDLIM_TSO,
	TCP_ESTATS_SNDLIM_FRAG,
	TCP_ESTATS_SNDLIM_NSTATES	/* Keep at end */
};


enum tcp_estats_addrtype {
	TCP_ESTATS_ADDRTYPE_IPV4 = 1,
	TCP_ESTATS_ADDRTYPE_IPV6 = 2
};

#ifdef CONFIG_TCP_ESTATS
extern struct jump_label_key tcp_estats_key;

#define TCP_ESTATS_CHECK(tp,expr) \
	do { \
		if (static_branch(&tcp_estats_key)) { \
			if ((tp)->tcp_stats) \
				(expr); \
		} \
	} while (0)

#define TCP_ESTATS_VAR_INC(tp,var) \
	TCP_ESTATS_CHECK(tp, ((tp)->tcp_stats->estats_vars.var)++)
#define TCP_ESTATS_VAR_DEC(tp,var) \
	TCP_ESTATS_CHECK(tp, ((tp)->tcp_stats->estats_vars.var)--)
#define TCP_ESTATS_VAR_ADD(tp,var,val) \
	TCP_ESTATS_CHECK(tp, ((tp)->tcp_stats->estats_vars.var) += (val))
#define TCP_ESTATS_VAR_SET(tp,var,val) \
	TCP_ESTATS_CHECK(tp, ((tp)->tcp_stats->estats_vars.var) = (val))
#define TCP_ESTATS_VAR_INC2(tp,var,offset) \
	TCP_ESTATS_CHECK(tp, ((tp)->tcp_stats->estats_vars.var[offset])++)
#define TCP_ESTATS_UPDATE(tp,func) \
	TCP_ESTATS_CHECK(tp, func)

/* The official MIB states are enumerated differently than
 * Linux's.  Use tcp_estats_state() to convert. */
enum tcp_estats_states {
	TCP_ESTATS_STATE_CLOSED = 1,
	TCP_ESTATS_STATE_LISTEN,
	TCP_ESTATS_STATE_SYNSENT,
	TCP_ESTATS_STATE_SYNRECEIVED,
	TCP_ESTATS_STATE_ESTABLISHED,
	TCP_ESTATS_STATE_FINWAIT1,
	TCP_ESTATS_STATE_FINWAIT2,
	TCP_ESTATS_STATE_CLOSEWAIT,
	TCP_ESTATS_STATE_LASTACK,
	TCP_ESTATS_STATE_CLOSING,
	TCP_ESTATS_STATE_TIMEWAIT,
	TCP_ESTATS_STATE_DELETECB
};

enum {
	TCP_ESTATS_TYPE_INTEGER = 0,
	TCP_ESTATS_TYPE_INTEGER32,
	TCP_ESTATS_TYPE_INET_ADDRESS_IPV4,
	TCP_ESTATS_TYPE_COUNTER32,
	TCP_ESTATS_TYPE_GAUGE32,
	TCP_ESTATS_TYPE_UNSIGNED32,
	TCP_ESTATS_TYPE_TIME_TICKS,
	TCP_ESTATS_TYPE_COUNTER64,
	TCP_ESTATS_TYPE_INET_PORT_NUMBER,
	TCP_ESTATS_TYPE_INET_ADDRESS,
	TCP_ESTATS_TYPE_INET_ADDRESS_IPV6,
	TCP_ESTATS_TYPE_OCTET = 12,
};

enum {
	CongCWR = 0,
	CongLoss,
	CongFastRtx,
	CongFRTO,
	CongFRTOLoss,
	CongMax
};

enum {
	belowDataWindow = 1,
	aboveDataWindow,
	belowAckWindow,
	aboveAckWindow,
	belowTSWindow,
	aboveTSWindow,
	dataCheckSum,
	otherSoftError,
	MaxSoftError,
};
/*
 * Variables that can be read and written directly.
 *
 * Should contain most variables from TCP-KIS 0.1.  Commented feilds are
 * either not implemented or have handlers and do not need struct storage.
 */
struct tcp_estats_directs {
	/* Connection table */
	u32			LocalAddressType;
	struct { u8 data[17]; }	LocalAddress;
	struct { u8 data[17]; }	RemAddress;
	u16			LocalPort;
	u16			RemPort;

	/* Perf table */
	u32		SegsOut;
	u32		DataSegsOut;
	u64		DataOctetsOut;
	u32		SegsRetrans;
	u32		OctetsRetrans;
	u32		SegsIn;
	u32		DataSegsIn;
	u64		DataOctetsIn;
	/*		ElapsedSecs */
	/*		ElapsedMicroSecs */
	/*		StartTimeStamp */
	/*		CurMSS */
	/*		PipeSize */
	u32		MaxPipeSize;
	/*		SmoothedRTT */
	/*		CurRTO */
	u32		CongSignals;
	u32		CongSignalsArray[CongMax];
	/*		CurCwnd */
	/*		CurSsthresh */
	u32		Timeouts;
	/*		CurRwinSent */
	u32		MaxRwinSent;
	u32		ZeroRwinSent;
	/*		CurRwinRcvd */
	u32		MaxRwinRcvd;
	u32		ZeroRwinRcvd;
	/*		SndLimTransRwin */
	/*		SndLimTransCwnd */
	/*		SndLimTransSnd */
	/*		SndLimTimeRwin */
	/*		SndLimTimeCwnd */
	/*		SndLimTimeSnd */
	u32		snd_lim_trans[TCP_ESTATS_SNDLIM_NSTATES];
	u32		snd_lim_time[TCP_ESTATS_SNDLIM_NSTATES];

	u32		ca_state_trans[TCP_CA_Loss + 1];
	u32		ca_state_time[TCP_CA_Loss + 1];

	/* Path table */
	u32		MaxRetranThresh;
	u32		NonRecovDAEpisodes;
	u32		SumOctetsReordered;
	u32		NonRecovDA;
	u32		SampleRTT;
	/*		RTTVar */
	u32		MaxRTT;
	u32		MinRTT;
	u64		SumRTT;
	u32		CountRTT;
	u32		MaxRTO;
	u32		MinRTO;
	u8		IpTtl;
	u8		IpTosIn;
	/*		IpTosOut */
	u32		PreCongSumCwnd;
	u32		PreCongSumRTT;
	u32		PostCongSumRTT;
	u32		PostCongCountRTT;
	u32		ECNsignals;
	u32		DupAckEpisodes;
	/*		RcvRTT */
	u32		DupAcksOut;
	u32		CERcvd;
	u32		ECESent;
	
	/* Stack table */
	u32		ActiveOpen;
	/*		MSSSent */
	/* 		MSSRcvd */
	/*		WinScaleSent */
	/*		WinScaleRcvd */
	/*		TimeStamps */
	/*		ECN */
	/*		WillSendSACK */
	/*		WillUseSACK */
	/*		State */
	/*		Nagle */
	u32		MaxSsCwnd;
	u32		MaxCaCwnd;
	u32		MaxSsthresh;
	u32		MinSsthresh;
	/*		InRecovery */
	u32		DupAcksIn;
	u32		SpuriousFrDetected;
	u32		SpuriousRtoDetected;
	u32		SoftErrors;
	u32		SoftErrorReason[MaxSoftError];
	u32		SlowStart;
	u32		CongAvoid;
	u32		OtherReductions;
	u32		CongOverCount;
	u32		FastRetran;
	u32		SubsequentTimeouts;
	/*		CurTimeoutCount */
	u32		AbruptTimeouts;
	u32		SACKsRcvd;
	u32		SACKBlocksRcvd;
	u32		SendStall;
	u32		DSACKDups;
	u32		MaxMSS;
	u32		MinMSS;
	u32		SndInitial;
	u32		RecInitial;
	u32		CurRetxQueue;
	u32		MaxRetxQueue;
	/*		CurReasmQueue */
	u32		MaxReasmQueue;

	/* App table */
	/*		SndUna */
	/*		SndNxt */
	u32		SndMax;
	u64		ThruOctetsAcked;
	/*		RcvNxt */
	u64		ThruOctetsReceived;
	/*		CurAppWQueue */
	u32		MaxAppWQueue;
	/*		CurAppRQueue */
	u32		MaxAppRQueue;
	
	/* Tune table */
	/*		LimCwnd */
	/*		LimSsthresh */
	/*		LimRwin */
	
	/* Extras */
	u32		OtherReductionsCV;
	u32		OtherReductionsCM;

	u32		InitCwnd;
	u32		InitCwndClamp;
	u32		InitSsthresh;
	u32		InitReordering;
	u32		InitSRTT;
	u32		InitRTTVar;
};

struct tcp_estats {
	int				estats_cid;

	struct sock			*estats_sk;

	atomic_t			estats_users;
	u8				estats_dead;

	struct list_head		estats_list;
	struct list_head		estats_hash_list;

	struct tcp_estats		*estats_death_next;

	int				estats_ca_state;
	ktime_t				estats_ca_state_ts;

	int				estats_limstate;
	ktime_t				estats_limstate_ts;
	ktime_t				estats_start_ts;
	ktime_t				estats_current_ts;
	struct timeval			estats_start_tv;

	struct tcp_estats_directs	estats_vars;
};


struct tcp_estats_var;
typedef void (*estats_rwfunc_t)(void *buf, struct tcp_estats *stats,
                                struct tcp_estats_var *vp);

/* The printed variable description should look something like this (in ASCII):
 * varname offset type
 * where offset is the offset into the file.
 */
struct tcp_estats_var {
	char		*name;
	u32		type;

	estats_rwfunc_t	read;
	unsigned long	read_data;	/* read handler-specific data */

	estats_rwfunc_t	write;
	unsigned long	write_data;	/* write handler-specific data */
};

extern int tcp_estats_conn_num;
extern struct tcp_estats_var tcp_estats_var_table[];
extern struct list_head *tcp_estats_head;
extern rwlock_t tcp_estats_linkage_lock;

/* For /proc/web100 */
extern struct tcp_estats *tcp_estats_lookup(int cid);

/* For the TCP code */
extern int __tcp_estats_create(struct sock *sk, enum tcp_estats_addrtype t);
extern void __tcp_estats_establish(struct sock *sk);
extern void __tcp_estats_destroy(struct sock *sk);

static inline int tcp_estats_create(struct sock *sk,
				enum tcp_estats_addrtype addrtype)
{
	if (static_branch(&tcp_estats_key))
		return __tcp_estats_create(sk, addrtype);
	tcp_sk(sk)->tcp_stats = NULL;
	return 0;
}

static inline void tcp_estats_establish(struct sock *sk)
{
	if (static_branch(&tcp_estats_key))
		__tcp_estats_establish(sk);
}

static inline void tcp_estats_destroy(struct sock *sk)
{
	__tcp_estats_destroy(sk);
}

extern void tcp_estats_free(struct tcp_estats *stats);

extern void tcp_estats_tune_sndbuf_ack(struct sock *sk);
extern void tcp_estats_tune_sndbuf_snd(struct sock *sk);
extern void tcp_estats_tune_rcvbuf(struct sock *sk);

extern void tcp_estats_update_snd_nxt(struct tcp_sock *tp);
extern void tcp_estats_update_acked(struct tcp_sock *tp, u32 ack);
extern void tcp_estats_update_rtt(struct sock *sk, unsigned long rtt_sample);
extern void tcp_estats_update_timeout(struct sock *sk);
extern void tcp_estats_update_mss(struct tcp_sock *tp);
extern void tcp_estats_update_rwin_rcvd(struct tcp_sock *tp);
extern void tcp_estats_update_sndlim(struct tcp_sock *tp, int why);
extern void tcp_estats_update_rcvd(struct tcp_sock *tp, u32 seq);
extern void tcp_estats_update_rwin_sent(struct tcp_sock *tp);
extern void tcp_estats_update_congestion(struct tcp_sock *tp, int reason);
extern void tcp_estats_update_post_congestion(struct tcp_sock *tp);
extern void tcp_estats_update_segsend(struct sock *sk, int len, int pcount,
                                      u32 seq, u32 end_seq, int flags);
extern void tcp_estats_update_segrecv(struct tcp_sock *tp, struct sk_buff *skb);
extern void tcp_estats_update_finish_segrecv(struct tcp_sock *tp);
extern void tcp_estats_update_rcvbuf(struct sock *sk, int rcvbuf);
extern void tcp_estats_update_writeq(struct sock *sk);
extern void tcp_estats_update_recvq(struct sock *sk);
extern void tcp_estats_update_ofoq(struct sock *sk);
extern void tcp_estats_update_reordering(struct tcp_sock *tp);
extern void tcp_estats_update_ca_state(struct sock *sk, int state);

extern void tcp_estats_init(void);
extern int tcp_estats_proc_init(void);

/* You may have to hold tcp_estats_linkage_lock here to prevent
   stats from disappearing. */
static inline void tcp_estats_use(struct tcp_estats *stats)
{
	atomic_inc(&stats->estats_users);
}

/* You MUST NOT hold tcp_estats_linkage_lock here. */
static inline void tcp_estats_unuse(struct tcp_estats *stats)
{
	if (atomic_dec_and_test(&stats->estats_users))
		tcp_estats_free(stats);
}

/* Length of various MIB data types. */
static inline int tcp_estats_var_len(struct tcp_estats_var *vp)
{
	switch (vp->type) {
	case TCP_ESTATS_TYPE_INET_PORT_NUMBER:
		return 2;
	case TCP_ESTATS_TYPE_INTEGER:
	case TCP_ESTATS_TYPE_INTEGER32:
	case TCP_ESTATS_TYPE_COUNTER32:
	case TCP_ESTATS_TYPE_GAUGE32:
	case TCP_ESTATS_TYPE_UNSIGNED32:
	case TCP_ESTATS_TYPE_TIME_TICKS:
		return 4;
	case TCP_ESTATS_TYPE_COUNTER64:
		return 8;
	case TCP_ESTATS_TYPE_INET_ADDRESS:
		return 17;
	case TCP_ESTATS_TYPE_OCTET:
		return 1;
	}
	
	printk(KERN_WARNING
	       "TCP ESTATS: Adding variable of unknown type %d.\n", vp->type);
	return 0;
}

#else /* !CONFIG_TCP_ESTATS */

#define sysctl_tcp_estats_enabled	(0)

#define TCP_ESTATS_VAR_INC(tp,var)	do {} while (0)
#define TCP_ESTATS_VAR_INC2(tp,var,offset)	do {} while (0)
#define TCP_ESTATS_VAR_DEC(tp,var)	do {} while (0)
#define TCP_ESTATS_VAR_SET(tp,var,val)	do {} while (0)
#define TCP_ESTATS_VAR_ADD(tp,var,val)	do {} while (0)
#define TCP_ESTATS_UPDATE(tp,func)	do {} while (0)

static inline void tcp_estats_init(void) { }
static inline void tcp_estats_establish(struct sock *sk) { }
static inline void tcp_estats_create(struct sock *sk, enum tcp_estats_addrtype t) { }
static inline void tcp_estats_destroy(struct sock *sk) { }

#endif /* CONFIG_TCP_ESTATS */

#endif /* _TCP_ESTATS_H */
