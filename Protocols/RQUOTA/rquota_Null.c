/*
 * Copyright CEA/DAM/DIF  2010
 *  Author: Philippe Deniel (philippe.deniel@cea.fr)
 *
 * --------------------------
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/file.h>
#include "hashtable.h"
#include "log.h"
#include "ganesha_rpc.h"
#include "nfs23.h"
#include "nfs4.h"
#include "nfs_core.h"
#include "cache_inode.h"
#include "nfs_exports.h"
#include "mount.h"
#include "rquota.h"
#include "nfs_proto_functions.h"

/**
 * @brief The RQUOTA proc null function, for all versions.
 *
 * @param[in]  arg    Ignored
 * @param[in]  export Ignored
 * @param[in]  worker Ignored
 * @param[in]  req    Ignored
 * @param[out] res    Ignored
 */

int rquota_Null(nfs_arg_t *arg,
		nfs_worker_data_t *worker,
		struct svc_req *req, nfs_res_t *res)
{
	LogFullDebug(COMPONENT_NFSPROTO,
		     "REQUEST PROCESSING: Calling rquota_Null");
	/* 0 is success */
	return 0;
}

/**
 * rquota_Null_Free: Frees the result structure allocated for rquota_Null
 *
 * Frees the result structure allocated for rquota_Null. Does Nothing in fact.
 *
 * @param res        [INOUT]   Pointer to the result structure.
 *
 */
void rquota_Null_Free(nfs_res_t *res)
{
	return;
}
