/*
   p0f - packet capture and overall host / flow bookkeeping
   --------------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#include "p0f-process.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <sys/file.h>

#include <sys/fcntl.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "alloc-inl.h"
#include "tcp.h"
#include "readfp.h"
#include "p0f.h"

#include "fp_tcp.h"
#include "fp_mtu.h"
#include "fp_http.h"
#include "p0f-config.h"
#include "p0f-debug.h"
#include "p0f-hash.h"
#include "p0f-types.h"
#include "p0f-utils.h"

processor::processor(const char *_read_file,
		const char* _log_file,
		u32 _max_conn,
		u32 _max_hosts,
		u32 _conn_max_age,
		u32 _host_idle_limit,
		u32 _hash_seed,
		s32 _link_type,
		u8 _daemon_mode){
    my_processor = this;

    max_conn = _max_conn;
    max_hosts = _max_hosts;
    conn_max_age = _conn_max_age;
    host_idle_limit = _host_idle_limit;
    hash_seed = _hash_seed;
    link_type = _link_type;
    daemon_mode = _daemon_mode;

    read_file = _read_file;

    log_file = _log_file;
	if(log_file)open_log();

	packet_cnt = 0;
	link_off = -1;
	bad_packets=0;

	host_by_age=NULL;
	newest_host=NULL;

	flow_by_age=NULL;
	newest_flow=NULL;

	cur_time=NULL;

	/* Bucketed hosts and flows: */
    for(uint32_t i = 0; i < HOST_BUCKETS;i++){
	   host_b[i]=NULL;
    }
    for(uint32_t i = 0; i < FLOW_BUCKETS;i++){
	   flow_b[i]=NULL;
    }
	host_cnt=0;
	flow_cnt=0;
}

processor::~processor(){

}

FILE *processor::get_log_stream(){ return lf; }
u32 processor::get_hash_seed() { return hash_seed; }

void processor::open_log(void) {

  struct stat st;
  s32 log_fd;

  log_fd = open((char*)log_file, O_WRONLY | O_APPEND | O_NOFOLLOW | O_LARGEFILE);

  if (log_fd >= 0) {

    if (fstat(log_fd, &st)) PFATAL("fstat() on '%s' failed.", log_file);

    if (!S_ISREG(st.st_mode)) FATAL("'%s' is not a regular file.", log_file);

  } else {

    if (errno != ENOENT) PFATAL("Cannot open '%s'.", log_file);

    log_fd = open((char*)log_file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                  LOG_MODE);

    if (log_fd < 0) PFATAL("Cannot open '%s'.", log_file);

  }

  if (flock(log_fd, LOCK_EX | LOCK_NB))
    FATAL("'%s' is being used by another process.", log_file);

  lf = fdopen(log_fd, "a");

  if (!lf) FATAL("fdopen() on '%s' failed.", log_file);

  SAYF("[+] Log file '%s' opened for writing.\n", log_file);

}

void processor::start_observation(const char* keyword, u8 field_cnt, u8 to_srv,
                       struct packet_flow* f) {

	the_record.clear();
	the_record.insert(std::pair<std::string,std::string>(std::string("keyword"),std::string(keyword)));
	the_record.insert(std::pair<std::string,std::string>(std::string("client_addr"),
			std::string((char *)utils::addr_to_str(f->client->addr, f->client->ip_ver))));
	the_record.insert(std::pair<std::string,std::string>(std::string("client_port"),
			std::to_string(f->cli_port)));
	the_record.insert(std::pair<std::string,std::string>(std::string("server_addr"),
			std::string((char *)utils::addr_to_str(f->server->addr, f->server->ip_ver))));
	the_record.insert(std::pair<std::string,std::string>(std::string("server_port"),
			std::to_string(f->srv_port)));

  if (obs_fields) FATAL("Premature end of observation.");

  if (!daemon_mode) {

    SAYF(".-[ %s/%u -> ", utils::addr_to_str(f->client->addr, f->client->ip_ver),
         f->cli_port);
    SAYF("%s/%u (%s) ]-\n|\n", utils::addr_to_str(f->server->addr, f->client->ip_ver),
         f->srv_port, keyword);

    SAYF("| %-8s = %s/%u\n", to_srv ? "client" : "server",
         utils::addr_to_str(to_srv ? f->client->addr :
         f->server->addr, f->client->ip_ver),
         to_srv ? f->cli_port : f->srv_port);

  }

  if (log_file) {

    u8 tmp[64];

    time_t ut = get_unix_time();
    struct tm* lt = localtime(&ut);

    strftime((char*)tmp, 64, "%Y/%m/%d %H:%M:%S", lt);

    LOGF("[%s] mod=%s|cli=%s/%u|",tmp, keyword, utils::addr_to_str(f->client->addr,
         f->client->ip_ver), f->cli_port);

    LOGF("srv=%s/%u|subj=%s", utils::addr_to_str(f->server->addr, f->server->ip_ver),
         f->srv_port, to_srv ? "cli" : "srv");

  }

  obs_fields = field_cnt;

}


/* Add log item. */

void processor::add_observation_field(const char* key, u8* value) {

  if (!obs_fields) FATAL("Unexpected observation field ('%s').", key);

  if (!daemon_mode)
    SAYF("| %-8s = %s\n", key, value ? value : (u8*)"???");

  if (log_file) LOGF("|%s=%s", key, value ? value : (u8*)"???");

  the_record.insert(std::pair<std::string, std::string>
               (std::string(key),std::string((char *)value)));

  obs_fields--;

  if (!obs_fields) {

    if (!daemon_mode) SAYF("|\n`----\n\n");

    if (log_file) LOGF("\n");

    LOGF("current record of size:%u contains:\n", the_record.size());
    for(auto r : the_record){
    	LOGF("key=%s value=%s\n",r.first.c_str(),r.second.c_str());
    }
    the_record_list.push_back(the_record);
    LOGF("the list of all records now has size %u\n", the_record_list.size());
    the_record_t::iterator key = the_record.find(std::string("keyword"));
    if(key != the_record.end()){
    	the_key_record_map_t::iterator key_rec = key_record_map.find(std::string(key->second));
    	if(key_rec == key_record_map.end()){
           key_record_map.insert(std::pair<std::string,the_record_t>(key->second,the_record));
           LOGF("inserted %s in key map size=%u\n",key->second.c_str(),key_record_map.size());
        } else {
           key_rec->second = the_record;
           LOGF("replaced the record for key %s size=%u\n",key->second.c_str(),key_record_map.size());
        }
    } else {
    	LOGF("ERROR: no keyword record found in the record\n");
    }

  }

}

void processor::set_fp_handlers(fp_http *a_fp_http, fp_tcp *a_fp_tcp, fp_mtu *a_fp_mtu){
	my_fp_http = a_fp_http;
	my_fp_tcp = a_fp_tcp;
	my_fp_mtu = a_fp_mtu;
}

/* Get unix time in milliseconds. */

u64 processor::get_unix_time_ms(void) {

  return ((u64)cur_time->tv_sec) * 1000 + (cur_time->tv_usec / 1000);
}


/* Get unix time in seconds. */

u32 processor::get_unix_time(void) {
  return cur_time->tv_sec;
}

u64 processor::get_packet_count() { return packet_cnt; }
u64 processor::get_bad_packet_count() { return bad_packets; }

/* Find link-specific offset (pcap knows, but won't tell). */

void processor::find_offset(const u8* data, s32 total_len) {

  u8 i;

  /* Check hardcoded values for some of the most common options. */

  switch (link_type) {

    case DLT_RAW:        link_off = 0;  return;

    case DLT_NULL:
    case DLT_PPP:        link_off = 4;  return;

    case DLT_LOOP:

#ifdef DLT_PPP_SERIAL
    case DLT_PPP_SERIAL:
#endif /* DLT_PPP_SERIAL */

    case DLT_PPP_ETHER:  link_off = 8;  return;

    case DLT_EN10MB:     link_off = 14; return;

#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL:  link_off = 16; return;
#endif /* DLT_LINUX_SLL */

    case DLT_PFLOG:      link_off = 28; return;

    case DLT_IEEE802_11: link_off = 32; return;
  }

  /* If this fails, try to auto-detect. There is a slight risk that if the
     first packet we see is maliciously crafted, and somehow gets past the
     configured BPF filter, we will configure the wrong offset. But that
     seems fairly unlikely. */

  for (i = 0; i < 40; i += 2, total_len -= 2) {

    if (total_len < MIN_TCP4) break;

    /* Perhaps this is IPv6? We check three things: IP version (first 4 bits);
       total length sufficient to accommodate IPv6 and TCP headers; and the
       "next protocol" field equal to PROTO_TCP. */

    if (total_len >= MIN_TCP6 && (data[i] >> 4) == IP_VER6) {

      struct ipv6_hdr* hdr = (struct ipv6_hdr*)(data + i);

      if (hdr->proto == PROTO_TCP) {

        DEBUG("[#] Detected packet offset of %u via IPv6 (link type %u).\n", i,
              link_type);
        link_off = i;
        break;

      }
      
    }

    /* Okay, let's try IPv4 then. The same approach, except the shortest packet
       size must be just enough to accommodate IPv4 + TCP (already checked). */

    if ((data[i] >> 4) == IP_VER4) {

      struct ipv4_hdr* hdr = (struct ipv4_hdr*)(data + i);

      if (hdr->proto == PROTO_TCP) {

        DEBUG("[#] Detected packet offset of %u via IPv4 (link type %u).\n", i,
              link_type);
        link_off = i;
        break;

      }

    }

  }

  /* If we found something, adjust for VLAN tags (ETH_P_8021Q == 0x8100). Else,
     complain once and try again soon. */

  if (link_off >= 4 && data[i-4] == 0x81 && data[i-3] == 0x00) {

    DEBUG("[#] Adjusting offset due to VLAN tagging.\n");
    link_off -= 4;

  } else if (link_off == -1) {

    link_off = -2;
    WARN("Unable to find link-specific packet offset. This is bad.");

  }

}


/* Parse PCAP input, with plenty of sanity checking. Store interesting details
   in a protocol-agnostic buffer that will be then examined upstream. */
void processor::static_parse_packet(u_char *user, const pcap_pkthdr *hdr, const u_char *data){
	processor *parser=reinterpret_cast<processor *>(user);
	// call parser for given object
    parser->parse_packet(hdr,data);
}

void processor::parse_packet(const pcap_pkthdr *hdr, const u_char *data){

  if(!my_fp_http ||
     !my_fp_tcp ||
	 !my_fp_mtu)ABORT("must call set_fp_handlers BEFORE parse_packet");

  struct tcp_hdr* tcp;
  struct packet_data pk;

  s32 packet_len;
  u32 tcp_doff;

  u8* opt_end;

  packet_cnt++;
  
  cur_time = (struct timeval*)&hdr->ts;

  if (!(packet_cnt % EXPIRE_INTERVAL)) expire_cache();

  /* Be paranoid about how much data we actually have off the wire. */

  packet_len = MIN(hdr->len, hdr->caplen);
  if (packet_len > SNAPLEN) packet_len = SNAPLEN;

  // DEBUG("[#] Received packet: len = %d, caplen = %d, limit = %d\n",
  //    hdr->len, hdr->caplen, SNAPLEN);

  /* Account for link-level headers. */

  if (link_off < 0) find_offset(data, packet_len);

  if (link_off > 0) {

    data += link_off;
    packet_len -= link_off;

  }

  /* If there is no way we could have received a complete TCP packet, bail
     out early. */

  if (packet_len < MIN_TCP4) {
    DEBUG("[#] Packet too short for any IPv4 + TCP headers, giving up!\n");
    return;
  }

  pk.quirks = 0;

  if ((*data >> 4) == IP_VER4) {

    /************************
     * IPv4 header parsing. *
     ************************/
    
    const struct ipv4_hdr* ip4 = (struct ipv4_hdr*)data;

    u32 hdr_len = (ip4->ver_hlen & 0x0F) * 4;
    u16 flags_off = ntohs(RD16(ip4->flags_off));
    u16 tot_len = ntohs(RD16(ip4->tot_len));

    /* If the packet claims to be shorter than what we received off the wire,
       honor this claim to account for etherleak-type bugs. */

    if (packet_len > tot_len) {
      packet_len = tot_len;
      // DEBUG("[#] ipv4.tot_len = %u, adjusted accordingly.\n", tot_len);
    }

    /* Bail out if the result leaves no room for IPv4 + TCP headers. */

    if (packet_len < MIN_TCP4) {
      DEBUG("[#] packet_len = %u. Too short for IPv4 + TCP, giving up!\n",
            packet_len);
      return;
    }

    /* Bail out if the declared length of IPv4 headers is nonsensical. */

    if (hdr_len < sizeof(struct ipv4_hdr)) {
      DEBUG("[#] ipv4.hdr_len = %u. Too short for IPv4, giving up!\n",
            hdr_len);
      return;
    }

    /* If the packet claims to be longer than the recv buffer, best to back
       off - even though we could just ignore this and recover. */

    if (tot_len > packet_len) {
      DEBUG("[#] ipv4.tot_len = %u but packet_len = %u, bailing out!\n",
            tot_len, packet_len);
      return;
    }

    /* And finally, bail out if after skipping the IPv4 header as specified
       (including options), there wouldn't be enough room for TCP. */

    if ((s32)(hdr_len + sizeof(struct tcp_hdr)) > packet_len) {
      DEBUG("[#] ipv4.hdr_len = %u, packet_len = %d, no room for TCP!\n",
            hdr_len, packet_len);
      return;
    }

    /* Bail out if the subsequent protocol is not TCP. */

    if (ip4->proto != PROTO_TCP) {
      DEBUG("[#] Whoa, IPv4 packet with non-TCP payload (%u)?\n", ip4->proto);
      return;
    }

    /* Ignore any traffic with MF or non-zero fragment offset specified. We
       can do enough just fingerprinting the non-fragmented traffic. */

    if (flags_off & ~(IP4_DF | IP4_MBZ)) {
      DEBUG("[#] Packet fragment (0x%04x), letting it slide!\n", flags_off);
      return;
    }

    /* Store some relevant information about the packet. */

    pk.ip_ver = IP_VER4;

    pk.ip_opt_len = hdr_len - 20;

    memcpy(pk.src, ip4->src, 4);
    memcpy(pk.dst, ip4->dst, 4);

    pk.tos = ip4->tos_ecn >> 2;

    pk.ttl = ip4->ttl;

    if (ip4->tos_ecn & (IP_TOS_CE | IP_TOS_ECT)) pk.quirks |= QUIRK_ECN;

    /* Tag some of the corner cases associated with implementation quirks. */
    
    if (flags_off & IP4_MBZ) pk.quirks |= QUIRK_NZ_MBZ;

    if (flags_off & IP4_DF) {

      pk.quirks |= QUIRK_DF;
      if (RD16(ip4->id)) pk.quirks |= QUIRK_NZ_ID;

    } else {

      if (!RD16(ip4->id)) pk.quirks |= QUIRK_ZERO_ID;

    }

    pk.tot_hdr = hdr_len;

    tcp = (struct tcp_hdr*)(data + hdr_len);
    packet_len -= hdr_len;
    
  } else if ((*data >> 4) == IP_VER6) {

    /************************
     * IPv6 header parsing. *
     ************************/
    
    const struct ipv6_hdr* ip6 = (struct ipv6_hdr*)data;
    u32 ver_tos = ntohl(RD32(ip6->ver_tos));
    u32 tot_len = ntohs(RD16(ip6->pay_len)) + sizeof(struct ipv6_hdr);

    /* If the packet claims to be shorter than what we received off the wire,
       honor this claim to account for etherleak-type bugs. */

    if (packet_len > (s32)tot_len) {
      packet_len = tot_len;
      // DEBUG("[#] ipv6.tot_len = %u, adjusted accordingly.\n", tot_len);
    }

    /* Bail out if the result leaves no room for IPv6 + TCP headers. */

    if (packet_len < MIN_TCP6) {
      DEBUG("[#] packet_len = %u. Too short for IPv6 + TCP, giving up!\n",
            packet_len);
      return;
    }

    /* If the packet claims to be longer than the data we have, best to back
       off - even though we could just ignore this and recover. */

    if ((s32)tot_len > packet_len) {
      DEBUG("[#] ipv6.tot_len = %u but packet_len = %u, bailing out!\n",
            tot_len, packet_len);
      return;
    }

    /* Bail out if the subsequent protocol is not TCP. One day, we may try
       to parse and skip IPv6 extensions, but there seems to be no point in
       it today. */

    if (ip6->proto != PROTO_TCP) {
      DEBUG("[#] IPv6 packet with non-TCP payload (%u).\n", ip6->proto);
      return;
    }

    /* Store some relevant information about the packet. */

    pk.ip_ver = IP_VER6;

    pk.ip_opt_len = 0;

    memcpy(pk.src, ip6->src, 16);
    memcpy(pk.dst, ip6->dst, 16);

    pk.tos = (ver_tos >> 22) & 0x3F;

    pk.ttl = ip6->ttl;

    if (ver_tos & 0xFFFFF) pk.quirks |= QUIRK_FLOW;

    if ((ver_tos >> 20) & (IP_TOS_CE | IP_TOS_ECT)) pk.quirks |= QUIRK_ECN;

    pk.tot_hdr = sizeof(struct ipv6_hdr);

    tcp = (struct tcp_hdr*)(ip6 + 1);
    packet_len -= sizeof(struct ipv6_hdr);

  } else {

    if (!bad_packets) {
      WARN("Unknown packet type %u, link detection issue?", *data >> 4);
      bad_packets = 1;
    }

    return;

  }

  /***************
   * TCP parsing *
   ***************/

  data = (u8*)tcp;

  tcp_doff = (tcp->doff_rsvd >> 4) * 4;

  /* As usual, let's start with sanity checks. */

  if (tcp_doff < sizeof(struct tcp_hdr)) {
    DEBUG("[#] tcp.hdr_len = %u, not enough for TCP!\n", tcp_doff);
    return;
  }

  if ((s32)tcp_doff > packet_len) {
    DEBUG("[#] tcp.hdr_len = %u, past end of packet!\n", tcp_doff);
    return;
  }

  pk.tot_hdr += tcp_doff;

  pk.sport = ntohs(RD16(tcp->sport));
  pk.dport = ntohs(RD16(tcp->dport));

  pk.tcp_type = tcp->flags & (TCP_SYN | TCP_ACK | TCP_FIN | TCP_RST);

  /* NUL, SYN+FIN, SYN+RST, FIN+RST, etc, should go to /dev/null. */

  if (((tcp->flags & TCP_SYN) && (tcp->flags & (TCP_FIN | TCP_RST))) ||
      ((tcp->flags & TCP_FIN) && (tcp->flags & TCP_RST)) ||
      !pk.tcp_type) {

    DEBUG("[#] Silly combination of TCP flags: 0x%02x.\n", tcp->flags);
    return;

  }

  pk.win = ntohs(RD16(tcp->win));

  pk.seq = ntohl(RD32(tcp->seq));

  /* Take note of miscellanous features and quirks. */

  if ((tcp->flags & (TCP_ECE | TCP_CWR)) || 
      (tcp->doff_rsvd & TCP_NS_RES)) pk.quirks |= QUIRK_ECN;

  if (!pk.seq) pk.quirks |= QUIRK_ZERO_SEQ;

  if (tcp->flags & TCP_ACK) {

    if (!RD32(tcp->ack)) pk.quirks |= QUIRK_ZERO_ACK;

  } else {

    /* A good proportion of RSTs tend to have "illegal" ACK numbers, so
       ignore these. */

    if (RD32(tcp->ack) & !(tcp->flags & TCP_RST)) {

      DEBUG("[#] Non-zero ACK on a non-ACK packet: 0x%08x.\n",
            ntohl(RD32(tcp->ack)));

      pk.quirks |= QUIRK_NZ_ACK;

    }

  }

  if (tcp->flags & TCP_URG) {

    pk.quirks |= QUIRK_URG;

  } else {

    if (RD16(tcp->urg)) {

      DEBUG("[#] Non-zero UPtr on a non-URG packet: 0x%08x.\n",
            ntohl(RD16(tcp->urg)));

      pk.quirks |= QUIRK_NZ_URG;

    }

  }

  if (tcp->flags & TCP_PUSH) pk.quirks |= QUIRK_PUSH;

  /* Handle payload data. */

  if ((s32)tcp_doff == packet_len) {

    pk.payload = NULL;
    pk.pay_len = 0;

  } else {

    pk.payload = (u8*)data + tcp_doff;
    pk.pay_len = packet_len - tcp_doff;

  }

  /**********************
   * TCP option parsing *
   **********************/

  opt_end = (u8*)data + tcp_doff; /* First byte of non-option data */
  data = (u8*)(tcp + 1);

  pk.opt_cnt     = 0;
  pk.opt_eol_pad = 0;
  pk.mss         = 0;
  pk.wscale      = 0;
  pk.ts1         = 0;

  /* Option parsing problems are non-fatal, but we want to keep track of
     them to spot buggy TCP stacks. */

  while (data < opt_end && pk.opt_cnt < MAX_TCP_OPT) {

    pk.opt_layout[pk.opt_cnt++] = *data;

    switch (*data++) {

      case TCPOPT_EOL:

        /* EOL is a single-byte option that aborts further option parsing.
           Take note of how many bytes of option data are left, and if any of
           them are non-zero. */

        pk.opt_eol_pad = opt_end - data;
        
        while (data < opt_end && !*data++);

        if (data != opt_end) {
          pk.quirks |= QUIRK_OPT_EOL_NZ;
          data = opt_end;
        }

        break;

      case TCPOPT_NOP:

        /* NOP is a single-byte option that does nothing. */

        break;
  
      case TCPOPT_MAXSEG:

        /* MSS is a four-byte option with specified size. */

        if (data + 3 > opt_end) {
          DEBUG("[#] MSS option would end past end of header (%u left).\n",
                opt_end - data);
          goto abort_options;
        }

        if (*data != 4) {
          DEBUG("[#] MSS option expected to have 4 bytes, not %u.\n", *data);
          pk.quirks |= QUIRK_OPT_BAD;
        }

        pk.mss = ntohs(RD16p(data+1));

        data += 3;

        break;

      case TCPOPT_WSCALE:

        /* WS is a three-byte option with specified size. */

        if (data + 2 > opt_end) {
          DEBUG("[#] WS option would end past end of header (%u left).\n",
                opt_end - data);
          goto abort_options;
        }

        if (*data != 3) {
          DEBUG("[#] WS option expected to have 3 bytes, not %u.\n", *data);
          pk.quirks |= QUIRK_OPT_BAD;
        }

        pk.wscale = data[1];

        if (pk.wscale > 14) pk.quirks |= QUIRK_OPT_EXWS;

        data += 2;

        break;

      case TCPOPT_SACKOK:

        /* SACKOK is a two-byte option with specified size. */

        if (data + 1 > opt_end) {
          DEBUG("[#] SACKOK option would end past end of header (%u left).\n",
                opt_end - data);
          goto abort_options;
        }

        if (*data != 2) {
          DEBUG("[#] SACKOK option expected to have 2 bytes, not %u.\n", *data);
          pk.quirks |= QUIRK_OPT_BAD;
        }

        data++;

        break;

      case TCPOPT_SACK:

        /* SACK is a variable-length option of 10 to 34 bytes. Because we don't
           know the size any better, we need to bail out if it looks wonky. */

        if (data == opt_end) {
          DEBUG("[#] SACK option without room for length field.");
          goto abort_options;
        }

        if (*data < 10 || *data > 34) {
          DEBUG("[#] SACK length out of range (%u), bailing out.\n", *data);
          goto abort_options;
        }

        if (data - 1 + *data > opt_end) {
          DEBUG("[#] SACK option (len %u) is too long (%u left).\n",
                *data, opt_end - data);
          goto abort_options;
        }

        data += *data - 1;

        break;

      case TCPOPT_TSTAMP:

        /* Timestamp is a ten-byte option with specified size. */

        if (data + 9 > opt_end) {
          DEBUG("[#] TStamp option would end past end of header (%u left).\n",
                opt_end - data);
          goto abort_options;
        }

        if (*data != 10) {
          DEBUG("[#] TStamp option expected to have 10 bytes, not %u.\n",
                *data);
          pk.quirks |= QUIRK_OPT_BAD;
        }

        pk.ts1 = ntohl(RD32p(data + 1));

        if (!pk.ts1) pk.quirks |= QUIRK_OPT_ZERO_TS1;

        if (pk.tcp_type == TCP_SYN && RD32p(data + 5)) {

          DEBUG("[#] Non-zero second timestamp: 0x%08x.\n",
                ntohl(*(u32*)(data + 5)));

          pk.quirks |= QUIRK_OPT_NZ_TS2;

        }

        data += 9;

        break;

      default:

        /* Unknown option, presumably with specified size. */

        if (data == opt_end) {
          DEBUG("[#] Unknown option 0x%02x without room for length field.",
                data[-1]);
          goto abort_options;
        }

        if (*data < 2 || *data > 40) {
          DEBUG("[#] Unknown option 0x%02x has invalid length %u.\n",
                data[-1], *data);
          goto abort_options;
        }

        if (data - 1 + *data > opt_end) {
          DEBUG("[#] Unknown option 0x%02x (len %u) is too long (%u left).\n",
                data[-1], *data, opt_end - data);
          goto abort_options;
        }

        data += *data - 1;

    }

  }

  if (data != opt_end) {

abort_options:

    DEBUG("[#] Option parsing aborted (cnt = %u, remainder = %u).\n",
          pk.opt_cnt, opt_end - data);

    pk.quirks |= QUIRK_OPT_BAD;

  }

  flow_dispatch(&pk);

}


/* Calculate hash bucket for packet_flow. Keep the hash symmetrical: switching
   source and dest should have no effect. */

u32 processor::get_flow_bucket(struct packet_data* pk) {

  u32 bucket;

  if (pk->ip_ver == IP_VER4) {
    bucket = hash32(pk->src, 4, hash_seed) ^ hash32(pk->dst, 4, hash_seed);
  } else {
    bucket = hash32(pk->src, 16, hash_seed) ^ hash32(pk->dst, 16, hash_seed);
  }

  bucket ^= hash32(&pk->sport, 2, hash_seed) ^ hash32(&pk->dport, 2, hash_seed);

  return bucket % FLOW_BUCKETS;

}


/* Calculate hash bucket for host_data. */

u32 processor::get_host_bucket(u8* addr, u8 ip_ver) {

  u32 bucket;

  bucket = hash32(addr, (ip_ver == IP_VER4) ? 4 : 16, hash_seed);

  return bucket % HOST_BUCKETS;

}


/* Look up host data. */

struct host_data* processor::lookup_host(u8* addr, u8 ip_ver) {

  u32 bucket = get_host_bucket(addr, ip_ver);
  struct host_data* h = host_b[bucket];

  while (CP(h)) {

    if (ip_ver == h->ip_ver &&
        !memcmp(addr, h->addr, (h->ip_ver == IP_VER4) ? 4 : 16))
      return h;

    h = h->next;

  }

  return NULL;

}


/* Destroy host data. */

void processor::destroy_host(struct host_data* h) {

  u32 bucket; 

  bucket = get_host_bucket(CP(h)->addr, h->ip_ver);

  if (h->use_cnt) FATAL("Attempt to destroy used host data.");

  DEBUG("[#] Destroying host data: %s (bucket %d)\n",
        utils::addr_to_str(h->addr, h->ip_ver), bucket);

  /* Remove it from the bucketed linked list. */

  if (CP(h->next)) h->next->prev = h->prev;
  
  if (CP(h->prev)) h->prev->next = h->next;
  else host_b[bucket] = h->next;

  /* Remove from the by-age linked list. */

  if (CP(h->newer)) h->newer->older = h->older;
  else newest_host = h->older;

  if (CP(h->older)) h->older->newer = h->newer;
  else host_by_age = h->newer; 

  /* Free memory. */

  ck_free((VOID_PTR)h->last_syn);
  ck_free((VOID_PTR)h->last_synack);

  ck_free((VOID_PTR)h->http_resp);
  ck_free((VOID_PTR)h->http_req_os);

  ck_free((VOID_PTR)h);

  host_cnt--;

}


/* Indiscriminately kill some of the older hosts. */

void processor::nuke_hosts(void) {

  u32 kcnt = 1 + (host_cnt * KILL_PERCENT / 100);
  struct host_data* target = host_by_age;

  if (!read_file)
    WARN("Too many host entries, deleting %u. Use -m to adjust.", kcnt);

  nuke_flows(1);

  while (kcnt && CP(target)) {
    struct host_data* next = target->older;
    if (!target->use_cnt) { kcnt--; destroy_host(target); }
    target = next;
  }

}
  


/* Create a minimal host data. */

struct host_data* processor::create_host(u8* addr, u8 ip_ver) {

  u32 bucket = get_host_bucket(addr, ip_ver);
  struct host_data* nh;

  if (host_cnt > max_hosts) nuke_hosts();

  DEBUG("[#] Creating host data: %s (bucket %u)\n",
        utils::addr_to_str(addr, ip_ver), bucket);

  nh = (host_data *)ck_alloc(sizeof(struct host_data));

  /* Insert into the bucketed linked list. */

  if (CP(host_b[bucket])) {
    host_b[bucket]->prev = nh;
    nh->next = host_b[bucket];
  }

  host_b[bucket] = nh;

  /* Insert into the by-age linked list. */
 
  if (CP(newest_host)) {

    newest_host->newer = nh;
    nh->older = newest_host;

  } else host_by_age = nh;

  newest_host = nh;

  /* Populate other data. */

  nh->ip_ver = ip_ver;
  memcpy(nh->addr, addr, (ip_ver == IP_VER4) ? 4 : 16);

  nh->last_seen = nh->first_seen = get_unix_time();

  nh->last_up_min     = -1;
  nh->last_class_id   = -1;
  nh->last_name_id    = -1;
  nh->http_name_id    = -1;
  nh->distance        = -1;

  host_cnt++;

  return nh;

}


/* Touch host data to make it more recent. */

void processor::touch_host(struct host_data* h) {

  CP(h);

  DEBUG("[#] Refreshing host data: %s\n", utils::addr_to_str(h->addr, h->ip_ver));

  if (h != CP(newest_host)) {

    /* Remove from the the by-age linked list. */

    CP(h->newer);
    h->newer->older = h->older;

    if (CP(h->older)) h->older->newer = h->newer;
    else host_by_age = h->newer; 

    /* Re-insert in front. */

    newest_host->newer = h;
    h->older = newest_host;
    h->newer = NULL;

    newest_host = h;

    /* This wasn't the only entry on the list, so there is no
       need to update the tail (host_by_age). */

  }

  /* Update last seen time. */

  h->last_seen = get_unix_time();

}



/* Destroy a flow. */

void processor::destroy_flow(struct packet_flow* f) {

  CP(f);
  CP(f->client);
  CP(f->server);

  DEBUG("[#] Destroying flow: %s/%u -> ",
        utils::addr_to_str(f->client->addr, f->client->ip_ver), f->cli_port);

  DEBUG("%s/%u (bucket %u)\n",
        utils::addr_to_str(f->server->addr, f->server->ip_ver), f->srv_port,
        f->bucket);

  /* Remove it from the bucketed linked list. */

  if (CP(f->next)) f->next->prev = f->prev;
  
  if (CP(f->prev)) f->prev->next = f->next;
  else { CP(flow_b[f->bucket]); flow_b[f->bucket] = f->next; }

  /* Remove from the by-age linked list. */

  if (CP(f->newer)) f->newer->older = f->older;
  else { CP(newest_flow); newest_flow = f->older; }

  if (CP(f->older)) f->older->newer = f->newer;
  else flow_by_age = f->newer; 

  /* Free memory, etc. */

  f->client->use_cnt--;
  f->server->use_cnt--;

  my_fp_http->free_sig_hdrs(&f->http_tmp);

  ck_free((VOID_PTR)f->request);
  ck_free((VOID_PTR)f->response);
  ck_free((VOID_PTR)f);

  flow_cnt--;  

}


/* Indiscriminately kill some of the oldest flows. */

void processor::nuke_flows(u8 silent) {

  u32 kcnt = 1 + (flow_cnt * KILL_PERCENT / 100);

  if (silent)
    DEBUG("[#] Pruning connections - trying to delete %u...\n",kcnt);
  else if (!read_file)
    WARN("Too many tracked connections, deleting %u. "
         "Use -m to adjust.", kcnt);

  while (kcnt-- && flow_by_age) destroy_flow(flow_by_age);

}



/* Create flow, and host data if necessary. If counts exceeded, prune old. */

struct packet_flow* processor::create_flow_from_syn(struct packet_data* pk) {

  u32 bucket = get_flow_bucket(pk);
  struct packet_flow* nf;

  if (flow_cnt > max_conn) nuke_flows(0);

  DEBUG("[#] Creating flow from SYN: %s/%u -> ",
        utils::addr_to_str(pk->src, pk->ip_ver), pk->sport);

  DEBUG("%s/%u (bucket %u)\n",
        utils::addr_to_str(pk->dst, pk->ip_ver), pk->dport, bucket);

  nf = (packet_flow *)ck_alloc(sizeof(struct packet_flow));

  nf->client = lookup_host(pk->src, pk->ip_ver);

  if (nf->client) touch_host(nf->client);
  else nf->client = create_host(pk->src, pk->ip_ver);

  nf->server = lookup_host(pk->dst, pk->ip_ver);

  if (nf->server) touch_host(nf->server);
  else nf->server = create_host(pk->dst, pk->ip_ver);

  nf->client->use_cnt++;
  nf->server->use_cnt++;

  nf->client->total_conn++;
  nf->server->total_conn++;

  /* Insert into the bucketed linked list.*/

  if (CP(flow_b[bucket])) {
    flow_b[bucket]->prev = nf;
    nf->next = flow_b[bucket];
  }

  flow_b[bucket] = nf;

  /* Insert into the by-age linked list */
 
  if (CP(newest_flow)) {
    newest_flow->newer = nf;
    nf->older = newest_flow;
  } else flow_by_age = nf;

  newest_flow = nf;

  /* Populate other data */

  nf->cli_port = pk->sport;
  nf->srv_port = pk->dport;
  nf->bucket   = bucket;
  nf->created  = get_unix_time();

  nf->next_cli_seq = pk->seq + 1;

  flow_cnt++;
  return nf;

}


/* Look up an existing flow. */

struct packet_flow* processor::lookup_flow(struct packet_data* pk, u8* to_srv) {

  u32 bucket = get_flow_bucket(pk);
  struct packet_flow* f = flow_b[bucket];

  while (CP(f)) {

    CP(f->client);
    CP(f->server);

    if (pk->ip_ver != f->client->ip_ver) goto lookup_next;

    if (pk->sport == f->cli_port && pk->dport == f->srv_port &&
        !memcmp(pk->src, f->client->addr, (pk->ip_ver == IP_VER4) ? 4 : 16) &&
        !memcmp(pk->dst, f->server->addr, (pk->ip_ver == IP_VER4) ? 4 : 16)) {

      *to_srv = 1;
      return f;

    }

    if (pk->dport == f->cli_port && pk->sport == f->srv_port &&
        !memcmp(pk->dst, f->client->addr, (pk->ip_ver == IP_VER4) ? 4 : 16) &&
        !memcmp(pk->src, f->server->addr, (pk->ip_ver == IP_VER4) ? 4 : 16)) {

      *to_srv = 0;
      return f;

    }

lookup_next:

    f = f->next;

  }

  return NULL;

}


/* Go through host and flow cache, expire outdated items. */

void processor::expire_cache(void) {
  struct host_data* target;
  static u32 pt;

  u32 ct = get_unix_time();

  if (ct == pt) return;
  pt = ct;

  DEBUG("[#] Cache expiration kicks in...\n");

  while (CP(flow_by_age) && ct - flow_by_age->created > conn_max_age)
    destroy_flow(flow_by_age);

  target = host_by_age;

  while (CP(target) && ct - target->last_seen > host_idle_limit * 60) {
    struct host_data* newer = target->newer;
    if (!target->use_cnt) destroy_host(target);
    target = newer;
  }

}


/* Insert data from a packet into a flow, call handlers as appropriate. */

void processor::flow_dispatch(struct packet_data* pk) {

  struct packet_flow* f;
  struct tcp_sig* tsig;
  u8 to_srv = 0;
  u8 need_more = 0;

  DEBUG("[#] Received TCP packet: %s/%u -> ",
        utils::addr_to_str(pk->src, pk->ip_ver), pk->sport);

  DEBUG("%s/%u (type 0x%02x, pay_len = %u)\n",
        utils::addr_to_str(pk->dst, pk->ip_ver), pk->dport, pk->tcp_type,
        pk->pay_len);
    
  f = lookup_flow(pk, &to_srv);

  switch (pk->tcp_type) {

    case TCP_SYN:

      if (f) {

        /* Perhaps just a simple dupe? */
        if (to_srv && f->next_cli_seq - 1 == pk->seq) return;

        DEBUG("[#] New SYN for an existing flow, resetting.\n");
        destroy_flow(f);

      }

      f = create_flow_from_syn(pk);

      tsig = my_fp_tcp->fingerprint_tcp(1, pk, f);

      /* We don't want to do any further processing on generic non-OS
         signatures (e.g. NMap). The easiest way to guarantee that is to 
         kill the flow. */

      if (!tsig && !f->sendsyn) {

        destroy_flow(f);
        return;

      }

      my_fp_mtu->fingerprint_mtu(1, pk, f);
      my_fp_tcp->check_ts_tcp(1, pk, f);

      if (tsig) {

        /* This can't be done in fingerprint_tcp because check_ts_tcp()
           depends on having original SYN / SYN+ACK data. */
 
        ck_free((VOID_PTR)f->client->last_syn);
        f->client->last_syn = tsig;

      }

      break;

    case TCP_SYN | TCP_ACK:

      if (!f) {

        DEBUG("[#] Stray SYN+ACK with no flow.\n");
        return;

      }

      /* This is about as far as we want to go with p0f-sendsyn. */

      if (f->sendsyn) {

        my_fp_tcp->fingerprint_tcp(0, pk, f);
        destroy_flow(f);
        return;

      }


      if (to_srv) {

        DEBUG("[#] SYN+ACK from client to server, trippy.\n");
        return;

      }

      if (f->acked) {

        if (f->next_srv_seq - 1 != pk->seq)
          DEBUG("[#] Repeated but non-identical SYN+ACK (0x%08x != 0x%08x).\n",
                f->next_srv_seq - 1, pk->seq);

        return;

      }

      f->acked = 1;

      tsig = my_fp_tcp->fingerprint_tcp(0, pk, f);

      /* SYN from real OS, SYN+ACK from a client stack. Weird, but whatever. */

      if (!tsig) {

        destroy_flow(f);
        return;

      }

      my_fp_mtu->fingerprint_mtu(0, pk, f);
      my_fp_tcp->check_ts_tcp(0, pk, f);

      ck_free((VOID_PTR)f->server->last_synack);
      f->server->last_synack = tsig;

      f->next_srv_seq = pk->seq + 1;

      break;

    case TCP_RST | TCP_ACK:
    case TCP_RST:
    case TCP_FIN | TCP_ACK:
    case TCP_FIN:

       if (f) {

         my_fp_tcp->check_ts_tcp(to_srv, pk, f);
         destroy_flow(f);

       }

       break;

    case TCP_ACK:

      if (!f) return;

      /* Stop there, you criminal scum! */

      if (f->sendsyn) {
        destroy_flow(f);
        return;
      }

      if (!f->acked) {

        DEBUG("[#] Never received SYN+ACK to complete handshake, huh.\n");
        destroy_flow(f);
        return;

      }

      if (to_srv) {

        /* We don't do stream reassembly, so if something arrives out of order,
           we won't catch it. Oh well. */

        if (f->next_cli_seq != pk->seq) {

          /* Not a simple dupe? */

          if (f->next_cli_seq - pk->pay_len != pk->seq)
            DEBUG("[#] Expected client seq 0x%08x, got 0x%08x.\n", f->next_cli_seq, pk->seq);
 
          return;
        }

        /* Append data */

        if (f->req_len < MAX_FLOW_DATA && pk->pay_len) {

          u32 read_amt = MIN(pk->pay_len, MAX_FLOW_DATA - f->req_len);

          f->request = (u8 *)ck_realloc_kb(f->request, f->req_len + read_amt + 1);
          memcpy(f->request + f->req_len, pk->payload, read_amt);
          f->req_len += read_amt;

        }

        my_fp_tcp->check_ts_tcp(1, pk, f);

        f->next_cli_seq += pk->pay_len;

      } else {

        if (f->next_srv_seq != pk->seq) {

          /* Not a simple dupe? */

          if (f->next_srv_seq - pk->pay_len != pk->seq)
            DEBUG("[#] Expected server seq 0x%08x, got 0x%08x.\n",
                  f->next_cli_seq, pk->seq);
 
          return;

        }

        /* Append data */

        if (f->resp_len < MAX_FLOW_DATA && pk->pay_len) {

          u32 read_amt = MIN(pk->pay_len, MAX_FLOW_DATA - f->resp_len);

          f->response = (u8 *)ck_realloc_kb(f->response, f->resp_len + read_amt + 1);
          memcpy(f->response + f->resp_len, pk->payload, read_amt);
          f->resp_len += read_amt;

        }

        my_fp_tcp->check_ts_tcp(0, pk, f);

        f->next_srv_seq += pk->pay_len;

      }

      if (!pk->pay_len) return;

      need_more |= my_fp_http->process_http(to_srv, f);

      if (!need_more) {

        DEBUG("[#] All modules done, no need to keep tracking flow.\n");
        destroy_flow(f);

      } else if (f->req_len >= MAX_FLOW_DATA && f->resp_len >= MAX_FLOW_DATA) {

        DEBUG("[#] Per-flow capture size limit exceeded.\n");
        destroy_flow(f);

      }

      break;

    default:

      WARN("Huh. Unexpected packet type 0x%02x in flow_dispatch().", pk->tcp_type);

  }

}


/* Add NAT score, check if alarm due. */

void processor::add_nat_score(u8 to_srv, struct packet_flow* f, u16 reason, u8 score) {

  static u8 rea[1024];

  struct host_data* hd;
  u8 *scores, *rptr = rea;
  u32 i;
  u8  over_5 = 0, over_2 = 0, over_1 = 0, over_0 = 0;

  if (to_srv) {

    hd = f->client;
    scores = hd->cli_scores;

  } else {

    hd = f->server;
    scores = hd->srv_scores;

  }

  memmove(scores, scores + 1, NAT_SCORES - 1);
  scores[NAT_SCORES - 1] = score;
  hd->nat_reasons |= reason;

  if (!score) return;

  for (i = 0; i < NAT_SCORES; i++) switch (scores[i]) {
    case 6 ... 255: over_5++;
    case 3 ... 5:   over_2++;
    case 2:         over_1++;
    case 1:         over_0++;
  }

  if (over_5 > 2 || over_2 > 4 || over_1 > 6 || over_0 > 8) {

    start_observation("ip sharing", 2, to_srv, f);

    reason = hd->nat_reasons;

    hd->last_nat = get_unix_time();

    memset(scores, 0, NAT_SCORES);
    hd->nat_reasons = 0;

  } else {

    /* Wait for something more substantial. */
    if (score == 1) return;

    start_observation("host change", 2, to_srv, f);

    hd->last_chg = get_unix_time();

  }

  *rptr = 0;

#define REAF(_par...) do { \
    rptr += snprintf((char*)rptr, 1024, _par); \
  } while (0) 

  if (reason & NAT_APP_SIG)  REAF(" app_vs_os");
  if (reason & NAT_OS_SIG)   REAF(" os_diff");
  if (reason & NAT_UNK_DIFF) REAF(" sig_diff");
  if (reason & NAT_TO_UNK)   REAF(" x_known");
  if (reason & NAT_TS)       REAF(" tstamp");
  if (reason & NAT_TTL)      REAF(" ttl");
  if (reason & NAT_PORT)     REAF(" port");
  if (reason & NAT_MSS)      REAF(" mtu");
  if (reason & NAT_FUZZY)    REAF(" fuzzy");

  if (reason & NAT_APP_VIA)  REAF(" via");
  if (reason & NAT_APP_DATE) REAF(" date");
  if (reason & NAT_APP_LB)   REAF(" srv_sig_lb");
  if (reason & NAT_APP_UA)   REAF(" ua_vs_os");

#undef REAF

  add_observation_field("reason", rea[0] ? (rea + 1) : NULL);

  OBSERVF("raw_hits", "%u,%u,%u,%u", over_5, over_2, over_1, over_0);

}


/* Verify if tool class (called from modules). */

void processor::verify_tool_class(u8 to_srv, struct packet_flow* f, u32* sys, u32 sys_cnt) {

  struct host_data* hd;
  u32 i;

  if (to_srv) hd = f->client; else hd = f->server;

  CP(sys);

  /* No existing data; although there is perhaps some value in detecting
     app-only conflicts in absence of other info, it's probably OK to just
     wait until more data becomes available. */

  if (hd->last_class_id == -1) return;

  for (i = 0; i < sys_cnt; i++)

    if ((sys[i] & SYS_CLASS_FLAG)) {

      if (SYS_NF(sys[i]) == (u32)hd->last_class_id) break;

    } else {

      if (SYS_NF(sys[i]) == (u32)hd->last_name_id) break;

    }

  /* Oops, a mismatch. */

  if (i == sys_cnt) {

    DEBUG("[#] Detected app not supposed to run on host OS.\n");
    add_nat_score(to_srv, f, NAT_APP_SIG, 4);

  } else {

    DEBUG("[#] Detected app supported on host OS.\n");
    add_nat_score(to_srv, f, 0, 0);

  }

}


/* Clean up everything. */

void processor::destroy_all_hosts(void) {

  while (flow_by_age) destroy_flow(flow_by_age);
  while (host_by_age) destroy_host(host_by_age);

}
