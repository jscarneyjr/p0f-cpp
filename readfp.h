/*
   p0f - p0f.fp file parser
   ------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_READFP_H
#define _HAVE_READFP_H

#include "p0f-types.h"

/* List of fingerprinting modules: */

#define CF_MOD_TCP           0x00       /* fp_tcp.c                           */
#define CF_MOD_MTU           0x01       /* fp_mtu.c                           */
#define CF_MOD_HTTP          0x02       /* fp_http.c                          */

/* Parser states: */

#define CF_NEED_SECT         0x00       /* Waiting for [...] or 'classes'     */
#define CF_NEED_LABEL        0x01       /* Waiting for 'label'                */
#define CF_NEED_SYS          0x02       /* Waiting for 'sys'                  */
#define CF_NEED_SIG          0x03       /* Waiting for signatures, if any.    */

/* Flag to distinguish OS class and name IDs */

#define SYS_CLASS_FLAG       (1<<31)
#define SYS_NF(_x)           ((_x) & ~SYS_CLASS_FLAG)
class processor;
class fp_http;
class fp_tcp;
class fp_mtu;

class fp_configurator {
public:
  fp_configurator(processor *a_processor);
  ~fp_configurator();

  void set_fp_handlers(fp_http *a_fp_http, fp_tcp *a_fp_tcp, fp_mtu *a_fp_mtu);

  void read_config(u8* fname);
  u32 lookup_name_id(u8* name, u8 len);
  u8 **fp_os_classes,                     /* Map of OS classes                  */
     **fp_os_names;                       /* Map of OS names                    */

private:
  u32 sig_cnt;                     /* Total number of p0f.fp sigs        */

  u8 state = CF_NEED_SECT,         /* Parser state (CF_NEED_*)           */
            mod_type,                     /* Current module (CF_MOD_*)          */
            mod_to_srv,                   /* Traffic direction                  */
            generic;                      /* Generic signature?                 */

  s32 sig_class;                   /* Signature class ID (-1 = userland) */
  s32 sig_name;                    /* Signature name                     */
  u8* sig_flavor;                  /* Signature flavor                   */

  u32* cur_sys;                    /* Current 'sys' values               */
  u32  cur_sys_cnt;                /* Number of 'sys' entries            */



  u32 class_cnt,                   /* Sizes for maps                     */
             name_cnt,
             label_id,                    /* Current label ID                   */
             line_no;                     /* Current line number                */
private:
  // globals
  processor *my_processor;
  fp_http *my_fp_http;
  fp_tcp *my_fp_tcp;
  fp_mtu *my_fp_mtu;

private:
  void config_parse_classes(u8* val);
  void config_parse_label(u8* val);
  void config_parse_sys(u8* val);
  void config_parse_line(u8* line);


};

#endif /* !_HAVE_READFP_H */
