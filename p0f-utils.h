/*
   p0f - packet capture and overall host / flow bookkeeping
   --------------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_PROCESS_UTILS_H
#define _HAVE_PROCESS_UTILS_H

#include <stdint.h>
#include "p0f-types.h"

class utils {
public:
    static u8* addr_to_str(u8* data, u8 ip_ver);
};

#endif /* !_HAVE_PROCESS_H */
