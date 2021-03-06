/*
   p0f - MTU matching
   ------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_FP_MTU_H
#define _HAVE_FP_MTU_H

#include "p0f-types.h"

/* Record for a TCP signature read from p0f.fp: */

struct mtu_sig_record {

  u8* name;
  u16 mtu;

};

#include "p0f-process.h"

struct packet_data;
struct packet_flow;

class fp_mtu {
public:
	fp_mtu(processor *a_processor);
	void mtu_register_sig(u8* name, u8* val, u32 line_no);

	void fingerprint_mtu(u8 to_srv, struct packet_data* pk, struct packet_flow* f);

	struct mtu_sig_record* sigs[SIG_BUCKETS];
	u32 sig_cnt[SIG_BUCKETS];
private:
	processor* my_processor;

};
#endif /* _HAVE_FP_MTU_H */
