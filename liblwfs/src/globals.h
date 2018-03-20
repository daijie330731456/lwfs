/*
   Copyright (c) 2009 LW, Inc. <http://www.lw.com>
   This file is part of LWFS.

   LWFS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published
   by the Free Software Foundation; either version 3 of the License,
   or (at your option) any later version.

   LWFS is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see
   <http://www.gnu.org/licenses/>.
*/

#ifndef _GLOBALS_H
#define _GLOBALS_H

#include "lwfs.h"
#include "xlator.h"

/* CTX */
#define CTX (lwfs_ctx_get())

lwfs_ctx_t *lwfs_ctx_get ();

/* THIS */
#define THIS (*__lwfs_this_location())

xlator_t **__lwfs_this_location ();
xlator_t *lwfs_this_get ();
int lwfs_this_set (xlator_t *);

void lwfs_central_log_flag_set ();
long lwfs_central_log_flag_get ();
void lwfs_central_log_flag_unset ();


/* init */
int lwfs_globals_init (void);

#endif /* !_GLOBALS_H */
