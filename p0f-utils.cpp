/*
   p0f - packet capture and overall host / flow bookkeeping
   --------------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */
#include <sys/time.h>
#include <cstdio>

#include "p0f-utils.h"
#include "tcp.h"

/* Convert IPv4 or IPv6 address to a human-readable form. */
u8* utils::addr_to_str(u8* data, u8 ip_ver) {

  static char tmp[128];

  /* We could be using inet_ntop(), but on systems that have older libc
     but still see passing IPv6 traffic, we would be in a pickle. */

  if (ip_ver == IP_VER4) {

    snprintf(tmp, 128, "%u.%u.%u.%u", data[0], data[1], data[2], data[3]);

  } else {

    snprintf(tmp,128, "%x:%x:%x:%x:%x:%x:%x:%x",
            (data[0] << 8) | data[1], (data[2] << 8) | data[3], 
            (data[4] << 8) | data[5], (data[6] << 8) | data[7], 
            (data[8] << 8) | data[9], (data[10] << 8) | data[11], 
            (data[12] << 8) | data[13], (data[14] << 8) | data[15]);

  }

  return (u8*)tmp;

}
