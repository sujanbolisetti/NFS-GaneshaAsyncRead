/*
 * nfs4_op_asyncread.c

 *
 *  Created on: Apr 22, 2015
 *      Author: root
 */

/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright CEA/DAM/DIF  (2008)
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
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
 *
 * ---------------------------------------
 */

/**
 * @file    nfs4_op_read.c
 * @brief   NFSv4 read operation
 *
 * This file implements NFS4_OP_READ within an NFSv4 compound call.
 */
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "hashtable.h"
#include "log.h"
#include "ganesha_rpc.h"
#include "nfs4.h"
#include "nfs_core.h"
#include "sal_functions.h"
#include "nfs_proto_functions.h"
#include "nfs_proto_tools.h"
#include "nfs_convert.h"
#include "nfs_rpc_callback.h"
#include <stdlib.h>
#include <unistd.h>
#include "fsal_pnfs.h"
#include "server_stats.h"
#include "export_mgr.h"

typedef struct async_args{
	struct nfs_argop4 *op;
	compound_data_t *data;
	cache_inode_io_direction_t io;
	struct io_info *info;
	struct req_op_context *op_ctx;
}async_args;


static void* nfs4_aysnc_read(void *asy_args)
{

	async_args *args= asy_args;
	struct nfs_argop4 *op = args->op;
	compound_data_t *data = args->data;
	struct io_info *info = NULL;
	cache_inode_io_direction_t io = CACHE_INODE_READ;
	nfs_cb_argop4 argop[1];
	uint64_t size = 0;
	size_t read_size = 0;
	uint64_t offset = 0;
	int status;
	bool eof_met = false;
	void *bufferdata = NULL;
	cache_inode_status_t cache_status = CACHE_INODE_SUCCESS;
	state_t *state_found = NULL;
	state_t *state_open = NULL;
	uint64_t file_size = 0;
	cache_entry_t *entry = NULL;
	bool sync = false;
	op_ctx = args->op_ctx;
	/* This flag is set to true in the case of an anonymous read
	   so that we know to release the state lock afterward.  The
	   state lock does not need to be held during a non-anonymous
	   read, since the open state itself prevents a conflict. */
	bool anonymous = false;

	memset(argop, 0, sizeof(nfs_cb_argop4));
	argop->argop = NFS4_OP_CB_ASYNC_READ;

	ASYNC_READ4args * const arg_ASYNCREAD4 = &op->nfs_argop4_u.opasync_read;

	CB_ASYNC_READ4args * const arg_CBASYNCREAD = &argop->nfs_cb_argop4_u.opcbasync_read;

	arg_CBASYNCREAD->status = NFS4_OK;


	CB_ASYNC_READ4argsok * const arg_CBASYNCREADok = &argop->nfs_cb_argop4_u.opcbasync_read.CB_ASYNC_READ4args_u.argok4;

	arg_CBASYNCREADok->reqid = arg_ASYNCREAD4->reqid;


	arg_CBASYNCREAD->status = nfs4_sanity_check_FH(data, REGULAR_FILE, true);
	if (arg_CBASYNCREAD->status != NFS4_OK)
		return NULL;

	entry = data->current_entry;
	/* Check stateid correctness and get pointer to state (also
	   checks for special stateids) */

	arg_CBASYNCREAD->status =
	    nfs4_Check_Stateid(&arg_ASYNCREAD4->stateid, entry, &state_found, data,
			       STATEID_SPECIAL_ANY, 0, FALSE, "READ");
	if (arg_CBASYNCREAD->status != NFS4_OK)
		return NULL;

	/* NB: After this point, if state_found == NULL, then the
	   stateid is all-0 or all-1 */

	if (state_found != NULL) {
		if (info)
			info->io_advise = state_found->state_data.io_advise;
		switch (state_found->state_type) {
		case STATE_TYPE_SHARE:
			state_open = state_found;
			/**
			 * @todo FSF: need to check against existing locks
			 */
			break;

		case STATE_TYPE_LOCK:
			state_open = state_found->state_data.lock.openstate;
			/**
			 * @todo FSF: should check that write is in
			 * range of an byte range lock...
			 */
			break;

		case STATE_TYPE_DELEG:
			state_open = NULL;
			/**
			 * @todo FSF: should check that this is a read
			 * delegation?
			 */
			break;

		default:
			arg_CBASYNCREAD->status = NFS4ERR_BAD_STATEID;
			LogDebug(COMPONENT_NFS_V4_LOCK,
				 "ASYNC with invalid statid of type %d",
				 state_found->state_type);
			return NULL;
		}

		/* This is a read operation, this means that the file
		   MUST have been opened for reading */
		if (state_open != NULL
		    && (state_open->state_data.share.
			share_access & OPEN4_SHARE_ACCESS_READ) == 0) {
			/* Even if file is open for write, the client
			   may do accidently read operation (caching).
			   Because of this, READ is allowed if not
			   explicitely denied.  See page 72 in RFC3530
			   for more details */

			if (state_open->state_data.share.
			    share_deny & OPEN4_SHARE_DENY_READ) {
				/* Bad open mode, return NFS4ERR_OPENMODE */
				arg_CBASYNCREAD->status = NFS4ERR_OPENMODE;
				LogDebug(COMPONENT_NFS_V4_LOCK,
					 "ASYNC state %p doesn't have "
					 "OPEN4_SHARE_ACCESS_READ",
					 state_found);
				return NULL;
			}
		}

		/**
		 * @todo : this piece of code looks a bit suspicious
		 *  (see Rong's mail)
		 *
		 * @todo: ACE: This works for now.  How do we want to
		 * handle owner confirmation across NFSv4.0/NFSv4.1?
		 * Do we want to mark every NFSv4.1 owner
		 * pre-confirmed, or make the check conditional on
		 * minorversion like we do here?
		 */
		switch (state_found->state_type) {
		case STATE_TYPE_SHARE:
			if ((data->minorversion == 0)
			    &&
			    (!(state_found->state_owner->so_owner.so_nfs4_owner.
			       so_confirmed))) {
				arg_CBASYNCREAD->status = NFS4ERR_BAD_STATEID;
				return NULL;
			}
			break;

		case STATE_TYPE_LOCK:
			/* Nothing to do */
			break;

		default:
			/* Sanity check: all other types are illegal.
			 * we should not got that place (similar check
			 * above), anyway it costs nothing to add this
			 * test */
			arg_CBASYNCREAD->status = NFS4ERR_BAD_STATEID;
			break;
		}
	} else {
		/* Special stateid, no open state, check to see if any
		   share conflicts */
		state_open = NULL;
		PTHREAD_RWLOCK_rdlock(&entry->state_lock);
		anonymous = true;

		/* Special stateid, no open state, check to see if any share
		   conflicts The stateid is all-0 or all-1 */
		arg_CBASYNCREAD->status =
		    nfs4_check_special_stateid(entry, "READ", FATTR4_ATTR_READ);
		if (arg_CBASYNCREAD->status != NFS4_OK) {
			PTHREAD_RWLOCK_unlock(&entry->state_lock);

		}
	}

	/** @todo this is racy, use cache_inode_lock_trust_attrs and
	 *        cache_inode_access_no_mutex
	 */
	if (state_open == NULL
	    && entry->obj_handle->attributes.owner !=
	    op_ctx->creds->caller_uid) {
		/* Need to permission check the read. */
		cache_status =
		    cache_inode_access(entry, FSAL_READ_ACCESS);

		if (cache_status == CACHE_INODE_FSAL_EACCESS) {
			/* Test for execute permission */
			cache_status =
			    cache_inode_access(entry,
					       FSAL_MODE_MASK_SET(FSAL_X_OK) |
					       FSAL_ACE4_MASK_SET
					       (FSAL_ACE_PERM_EXECUTE));
		}

		if (cache_status != CACHE_INODE_SUCCESS) {
			arg_CBASYNCREAD->status = nfs4_Errno(cache_status);
			goto done;
		}
	}

	/* Get the size and offset of the read operation */
	offset = arg_ASYNCREAD4->offset;
	size = arg_ASYNCREAD4->count;

	if (op_ctx->export->MaxOffsetRead < UINT64_MAX) {
		LogFullDebug(COMPONENT_NFS_V4,
			     "Read offset=%" PRIu64 " count=%zd "
			     "MaxOffSet=%" PRIu64, offset, size,
			     op_ctx->export->MaxOffsetRead);

		if ((offset + size) > op_ctx->export->MaxOffsetRead) {
			LogEvent(COMPONENT_NFS_V4,
				 "A client tryed to violate max "
				 "file size %" PRIu64 " for exportid #%hu",
				 op_ctx->export->MaxOffsetRead,
				 op_ctx->export->export_id);

			arg_CBASYNCREAD->status = NFS4ERR_DQUOT;
			goto done;
		}
	}

	if (size > op_ctx->export->MaxRead) {
		/* the client asked for too much data, this should normally
		   not happen because client will get FATTR4_MAXREAD value
		   at mount time */

		if (info == NULL ||
		    info->io_content.what != NFS4_CONTENT_HOLE) {
			LogFullDebug(COMPONENT_NFS_V4,
				     "ASYNC requested size = %"PRIu64
				     " ASYNC allowed size = %" PRIu64,
				     size, op_ctx->export->MaxRead);
			size = op_ctx->export->MaxRead;
		}
	}

	/* If size == 0, no I/O is to be made and everything is
	   alright */
	if (size == 0) {
		/* A size = 0 can not lead to EOF */
		arg_CBASYNCREADok->eof = false;
		//arg_CBASYNCREADok->data = 0;
		arg_CBASYNCREAD->status = NFS4_OK;
		goto done;
	}

	/* Some work is to be done */
	bufferdata = gsh_malloc_aligned(4096, size);

	if (bufferdata == NULL) {
		LogEvent(COMPONENT_NFS_V4, "FAILED to allocate bufferdata");
		arg_CBASYNCREAD->status = NFS4ERR_SERVERFAULT;
		goto done;
	}

	if (!anonymous && data->minorversion == 0) {
		op_ctx->clientid =
		    &state_found->state_owner->so_owner.so_nfs4_owner.
		    so_clientid;
	}


	cache_status =
	    cache_inode_rdwr_plus(entry, io, offset, size, &read_size,
				  bufferdata, &eof_met, &sync, info);
	if (cache_status != CACHE_INODE_SUCCESS) {
		arg_CBASYNCREAD->status = nfs4_Errno(cache_status);
		gsh_free(bufferdata);
		//res_READ4->READ4res_u.resok4.data.data_val = NULL;
		goto done;
	}

	if (cache_inode_size(entry, &file_size) !=
	    CACHE_INODE_SUCCESS) {
		arg_CBASYNCREAD->status = nfs4_Errno(cache_status);
		gsh_free(bufferdata);
		//res_READ4->READ4res_u.resok4.data.data_val = NULL;
		goto done;
	}

	if (!anonymous && data->minorversion == 0)
		op_ctx->clientid = NULL;

	LogFullDebug(COMPONENT_NFS_V4,
		     "NFS4_ASYNC_OP_READ: offset = %" PRIu64
		     " read length = %zu eof=%u", offset, read_size, eof_met);

	/* Is EOF met or not ? */
	arg_CBASYNCREADok->eof = (eof_met
					    || ((offset + read_size) >=
						file_size));

	arg_CBASYNCREADok->data.data_len = read_size;
	arg_CBASYNCREADok->data.data_val = bufferdata;

	LogFullDebug(COMPONENT_NFS_V4,
				"NFS4_ASYNC_OP_READ DATA: data = %s",arg_CBASYNCREADok->data.data_val);

	/* Say it is ok */
	arg_CBASYNCREAD->status = NFS4_OK;
	printf(" call states %d\n",cb_async_read(state_found,argop));

 done:
 	 printf("done");

 	printf("done after");
}


static int32_t cbasync_read_completion_func(rpc_call_t *call,
					   rpc_call_hook hook, void *arg,
					   uint32_t flags)
{
	char *fh;
	nfs_client_id_t *clid;

	LogDebug(COMPONENT_NFS_CB, "%p %s", call,
		 (hook ==
		  RPC_CALL_ABORT) ? "RPC_CALL_ABORT" : "RPC_CALL_COMPLETE");
	clid = (nfs_client_id_t *)arg;
	switch (hook) {
	case RPC_CALL_COMPLETE:
		/* potentially, do something more interesting here */
		LogDebug(COMPONENT_NFS_CB, "call result: %d", call->stat);
		fh = call->cbt.v_u.v4.args.argarray.argarray_val->
		    nfs_cb_argop4_u.opcbrecall.fh.nfs_fh4_val;
		/* Mark the channel down if the rpc call failed */
		/** @todo: what to do about server issues which made the RPC
		 *         call fail?
		 */
		if (call->stat != RPC_SUCCESS) {
			pthread_mutex_lock(&clid->cid_mutex);
			clid->cb_chan_down = true;
			pthread_mutex_unlock(&clid->cid_mutex);
		}
		gsh_free(fh);
		cb_compound_free(&call->cbt);
		break;
	default:
		LogDebug(COMPONENT_NFS_CB, "%p unknown hook %d", call, hook);
		break;
	}
	return 0;
}


int cb_async_read(state_t *state_found,nfs_cb_argop4 *argop){

		int32_t code = 0;
		rpc_call_channel_t *chan;
		rpc_call_t *call;
		nfs_client_id_t *clid = NULL;



		code = nfs_client_id_get_confirmed(state_found->state_owner->so_owner.so_nfs4_owner.so_clientid, &clid);

			if (code != CLIENT_ID_SUCCESS) {
				LogCrit(COMPONENT_NFS_CB, "No clid record  code %d", code);
			}


			/* Attempt a recall only if channel state is UP */
				pthread_mutex_lock(&clid->cid_mutex);
				if (clid->cb_chan_down) {
					pthread_mutex_unlock(&clid->cid_mutex);
					LogCrit(COMPONENT_NFS_CB,
						"Call back channel down, not issuing a recall");
					return NFS_CB_CALL_ABORTED;
				}
				pthread_mutex_unlock(&clid->cid_mutex);

				chan = nfs_rpc_get_chan(clid, NFS_RPC_FLAG_NONE);
					if (!chan) {
						LogCrit(COMPONENT_NFS_CB, "nfs_rpc_get_chan failed");
						/* TODO: move this to nfs_rpc_get_chan ? */
						pthread_mutex_lock(&clid->cid_mutex);
						clid->cb_chan_down = true;
						pthread_mutex_unlock(&clid->cid_mutex);
						return NFS_CB_CALL_ABORTED;
					}
					if (!chan->clnt) {
						LogCrit(COMPONENT_NFS_CB, "nfs_rpc_get_chan failed (no clnt)");
						pthread_mutex_lock(&clid->cid_mutex);
						clid->cb_chan_down = true;
						pthread_mutex_unlock(&clid->cid_mutex);
						return NFS_CB_CALL_ABORTED;
					}
					/* allocate a new call--freed in completion hook */
					call = alloc_rpc_call();
					call->chan = chan;

					cb_compound_init_v4(&call->cbt, 6, 1,
								    clid->cid_cb.v40.cb_callback_ident, "testing!!!",
								    10);
					/* add ops, till finished (dont exceed count) */
					cb_compound_add_op(&call->cbt, argop);
//
					/* set completion hook  TO DO */
					call->call_hook = cbasync_read_completion_func;
					nfs_rpc_submit_call(call, clid, NFS_RPC_FLAG_NONE);
					return call->states;

}





/**
 * @brief The NFS4_OP_READ operation
 *
 * This functions handles the READ operation in NFSv4.0 This
 * function can be called only from nfs4_Compound.
 *
 * @param[in]     op    The nfs4_op arguments
 * @param[in,out] data  The compound request's data
 * @param[out]    resp  The nfs4_op results
 *
 * @return Errors as specified by RFC3550 RFC5661 p. 371.
 */


int nfs4_op_async_read(struct nfs_argop4 *op, compound_data_t *data,
		 struct nfs_resop4 *resp)
{
	ASYNC_READ4res * const res_ASYNCREAD4 = &resp->nfs_resop4_u.opasync_read;
	res_ASYNCREAD4->status = NFS4_OK;
	resp->resop = NFS4_OP_ASYNC_READ;
	pthread_t thread;
	async_args *args = gsh_malloc(sizeof(struct async_args));
	struct nfs_argop4 *argop = gsh_malloc(sizeof(struct nfs_argop4));
	compound_data_t *arg_data = gsh_malloc(sizeof(compound_data_t));
	struct req_op_context *arg_op_ctx = gsh_malloc(sizeof(struct req_op_context));
	memcpy(argop,op,sizeof(struct nfs_argop4));
	memcpy(arg_data,data,sizeof(compound_data_t));
	memcpy(arg_op_ctx,op_ctx,sizeof(struct req_op_context));
	args->op=argop;
	args->data = arg_data;
	args->op_ctx = arg_op_ctx;

	pthread_create(&thread, NULL,nfs4_aysnc_read,(void*)args);
	return res_ASYNCREAD4->status;
}

/**
 * @brief Free data allocated for READ result.
 *
 * This function frees any data allocated for the result of the
 * NFS4_OP_READ operation.
 *
 * @param[in,out] resp  Results fo nfs4_op
 *
 */
void nfs4_op_async_read_Free(nfs_resop4 *res)
{
//	ASYNC_READ4res *resp = &res->nfs_resop4_u.opread;
//
//	if (resp->status == NFS4_OK)
//		if (resp->READ4res_u.resok4.data.data_val != NULL)
//			gsh_free(resp->READ4res_u.resok4.data.data_val);
	return;
}				/* nfs4_op_read_Free */







