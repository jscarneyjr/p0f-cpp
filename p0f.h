/*
   p0f - exports from the main routine
   -----------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_P0F_H
#define _HAVE_P0F_H
#include "p0f-process.h"
#include "p0f-types.h"

extern u8  daemon_mode;
extern s32 link_type;
extern u32 max_conn, max_hosts, conn_max_age, host_idle_limit, hash_seed;
extern u8* read_file;

#include "p0f-api.h"

struct api_client {

  s32 fd;                               /* -1 if slot free                    */

  struct p0f_api_query in_data;         /* Query recv buffer                  */
  u32 in_off;                           /* Query buffer offset                */

  struct p0f_api_response out_data;     /* Response transmit buffer           */
  u32 out_off;                          /* Response buffer offset             */

};

#endif /* !_HAVE_P0F_H */
