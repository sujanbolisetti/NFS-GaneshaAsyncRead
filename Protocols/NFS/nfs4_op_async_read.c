/*
 * nfs4_op_asyncread.c

 *
 *  Created on: Apr 22, 2015
 *      Author: root
 */

/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Authors:
 * 		Sujan Bolisetti
 * 		Harshavardhan
 * 		Ravichandra
 * ---------------------------------------
 */

/**
 * @file    nfs4_aync_op_read.c
 * @brief   NFSv4 Asynchronous Read Operation
 *
 * This file implements NFS4_OP_ASYNC_READ within an NFSv4 compound call.
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

/*
 *	Actual asynchronous read code
 *
 *  @param[in]     op    The nfs4_op arguments
 *  @param[in,out] data  The compound request's data
 *  @param[in] enqueued thread context(initial thread which has sent reply to client)
 *
 *  This code will be similar to op_read as both will be ending up performing actual file
 *  system read.
 *
 */

int nfs4_aysnc_read(struct nfs_argop4 *op,compound_data_t *data, struct req_op_context *arg_op_ctx)
{

	struct io_info *info = NULL;
	// this can be here or in the parameter.
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
	op_ctx = arg_op_ctx;
	/* This flag is set to true in the case of an anonymous read
	   so that we know to release the state lock afterward.  The
	   state lock does not need to be held during a non-anonymous
	   read, since the open state itself prevents a conflict. */
	bool anonymous = false;

	memset(argop, 0, sizeof(nfs_cb_argop4));

	argop->argop = NFS4_OP_CB_ASYNC_READ;

	ASYNC_READ4args * const arg_ASYNCREAD4 = &op->nfs_argop4_u.opasync_read;
	CB_ASYNC_READ4args * const arg_CBASYNCREAD = &argop->nfs_cb_argop4_u.opcbasync_read;
	CB_ASYNC_READ4argsok * const arg_CBASYNCREADok = &argop->nfs_cb_argop4_u.opcbasync_read.CB_ASYNC_READ4args_u.argok4;

	arg_CBASYNCREAD->status = NFS4_OK;

	arg_CBASYNCREADok->reqid = arg_ASYNCREAD4->reqid;

	// Asynchronous read is only allowed on a regular files hence we are checking.
	arg_CBASYNCREAD->status = nfs4_sanity_check_FH(data, REGULAR_FILE, true);
	if (arg_CBASYNCREAD->status != NFS4_OK)
		return arg_CBASYNCREAD->status;

	entry = data->current_entry;
	/* Check stateid correctness and get pointer to state (also
	   checks for special stateids) */

	arg_CBASYNCREAD->status =
			nfs4_Check_Stateid(&arg_ASYNCREAD4->stateid, entry, &state_found, data,
					STATEID_SPECIAL_ANY, 0, FALSE, "READ");

	if (arg_CBASYNCREAD->status != NFS4_OK)
		return arg_CBASYNCREAD->status;

	/* After this point, if state_found == NULL, then the
	   stateid is all-0 or all-1 */

	if (state_found != NULL) {
		if (info)
			info->io_advise = state_found->state_data.io_advise;
		switch (state_found->state_type) {
		case STATE_TYPE_SHARE:
			state_open = state_found;
			break;

		case STATE_TYPE_LOCK:
			state_open = state_found->state_data.lock.openstate;
			break;

		case STATE_TYPE_DELEG:
			state_open = NULL;
			break;

		default:
			arg_CBASYNCREAD->status = NFS4ERR_BAD_STATEID;
			LogDebug(COMPONENT_NFS_V4_LOCK,
					"ASYNC with invalid stateid of type %d",
					state_found->state_type);
			return arg_CBASYNCREAD->status;
		}

		if (state_open != NULL
				&& (state_open->state_data.share.
						share_access & OPEN4_SHARE_ACCESS_READ) == 0) {
			if (state_open->state_data.share.
					share_deny & OPEN4_SHARE_DENY_READ) {
				/* Bad open mode, return NFS4ERR_OPENMODE */
				arg_CBASYNCREAD->status = NFS4ERR_OPENMODE;
				LogDebug(COMPONENT_NFS_V4_LOCK,
						"ASYNC state %p doesn't have "
						"OPEN4_SHARE_ACCESS_READ",
						state_found);
				return arg_CBASYNCREAD->status;
			}
		}

		switch (state_found->state_type) {
		case STATE_TYPE_SHARE:
			if ((data->minorversion == 0)
					&&
					(!(state_found->state_owner->so_owner.so_nfs4_owner.
							so_confirmed))) {
				arg_CBASYNCREAD->status = NFS4ERR_BAD_STATEID;
				return arg_CBASYNCREAD->status;
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
			return arg_CBASYNCREAD->status;
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
			return arg_CBASYNCREAD->status;
		}
	}

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
				"Async Read offset=%" PRIu64 " count=%zd "
				"MaxOffSet=%" PRIu64, offset, size,
				op_ctx->export->MaxOffsetRead);

		if ((offset + size) > op_ctx->export->MaxOffsetRead) {
			LogEvent(COMPONENT_NFS_V4,
					"A client tried to violate max "
					"file size %" PRIu64 " for export id #%hu",
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
		arg_CBASYNCREADok->data.data_len =0;
		arg_CBASYNCREADok->data.data_val = NULL;
		arg_CBASYNCREAD->status = NFS4_OK;
		goto done;
	}

	bufferdata = gsh_malloc_aligned(4096, size);

	if (bufferdata == NULL) {
		LogEvent(COMPONENT_NFS_V4, "FAILED to allocate buffer data");
		arg_CBASYNCREAD->status = NFS4ERR_SERVERFAULT;
		goto done;
	}

	if (!anonymous && data->minorversion == 0) {
		op_ctx->clientid =
				&state_found->state_owner->so_owner.so_nfs4_owner.
				so_clientid;
	}

	/* Calling the file system read */
	cache_status =
			cache_inode_rdwr_plus(entry, io, offset, size, &read_size,
					bufferdata, &eof_met, &sync, info);
	if (cache_status != CACHE_INODE_SUCCESS) {
		arg_CBASYNCREAD->status = nfs4_Errno(cache_status);
		gsh_free(bufferdata);
		arg_CBASYNCREADok->data.data_val = NULL;
		goto done;
	}

	if (cache_inode_size(entry, &file_size) !=
			CACHE_INODE_SUCCESS) {
		arg_CBASYNCREAD->status = nfs4_Errno(cache_status);
		gsh_free(bufferdata);
		arg_CBASYNCREADok->data.data_val = NULL;
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
		if (anonymous)
			PTHREAD_RWLOCK_unlock(&entry->state_lock);
		server_stats_io_done(size, read_size,
			(arg_CBASYNCREAD->status == NFS4_OK) ? true : false,
					false);

	return arg_CBASYNCREAD->status;
}


static int32_t cbasync_read_completion_func(rpc_call_t *call,
		rpc_call_hook hook, void *arg,
		uint32_t flags)
{
		nfs_client_id_t *clid;

		LogDebug(COMPONENT_NFS_CB, "%p %s", call,
			 (hook ==
			  RPC_CALL_ABORT) ? "RPC_CALL_ABORT" : "RPC_CALL_COMPLETE");
		clid = (nfs_client_id_t *)arg;
		switch (hook) {
		case RPC_CALL_COMPLETE:
			/* potentially, do something more interesting here */
			LogDebug(COMPONENT_NFS_CB, "call result: %d", call->stat);

			if (call->stat != RPC_SUCCESS) {
				pthread_mutex_lock(&clid->cid_mutex);
				clid->cb_chan_down = true;
				pthread_mutex_unlock(&clid->cid_mutex);
			}

			cb_compound_free(&call->cbt);
			break;
		default:
			LogDebug(COMPONENT_NFS_CB, "%p unknown hook %d", call, hook);
			break;
		}
		return 0;
}

/**
 * @brief Free the data buffer allocated in cb_asyncread
 *
 * @param[in] op Operation to free
 */

static void free_cb_asyncread(nfs_cb_argop4 *op)
{
		CB_ASYNC_READ4args *cb_req = &op->nfs_cb_argop4_u.opcbasync_read;

		if (cb_req->status == NFS4_OK)
			if (cb_req->CB_ASYNC_READ4args_u.argok4.data.data_val != NULL)
				gsh_free(cb_req->CB_ASYNC_READ4args_u.argok4.data.data_val);

		return;
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

	PTHREAD_RWLOCK_wrlock(&state_found->state_entry->state_lock);

	code = nfs_rpc_v41_single(clid, argop,
			&state_found->state_refer, cbasync_read_completion_func,
			clid, free_cb_asyncread);

	if(code !=0){
		printf("RPC call back failed");
	}
	else{
		printf("success");
	}
	PTHREAD_RWLOCK_unlock(&state_found->state_entry->state_lock);
	return code;

}

/**
 * @brief The NFS4_OP_ASYNC_READ operation
 *
 * This functions handles the ASYNC READ operation in NFSv4.1 This
 * function can be called only from nfs4_Compound.
 *
 * @param[in]     op    The nfs4_op arguments
 * @param[in,out] data  The compound request's data
 * @param[out]    resp  The nfs4_op results
 *
 *
 */

int nfs4_op_async_read(struct nfs_argop4 *op, compound_data_t *data,
		struct nfs_resop4 *resp)
{
	ASYNC_READ4res * const res_ASYNCREAD4 = &resp->nfs_resop4_u.opasync_read;
	// creating the request for actual asynchronous read
	request_data_t *nfsreq;

	nfsreq = pool_alloc(request_pool, NULL);
	if (!nfsreq) {
		LogMajor(COMPONENT_DISPATCH,
				"Unable to allocate request. Exiting...");
		Fatal();
	}
	nfsreq->r_u.nfs = pool_alloc(request_data_pool, NULL);
	if (!nfsreq->r_u.nfs) {
		LogMajor(COMPONENT_DISPATCH,
				"Empty request data pool! Exiting...");
		Fatal();
	}

	nfsreq->r_u.nfs->cb_arg_nfs.cb_arg_compound.argarray.argarray_val = gsh_malloc(sizeof(nfs_cb_argop4));
	nfsreq->r_u.nfs->cb_arg_nfs.cb_arg_compound.argarray.argarray_val->argop = NFS4_OP_CB_ASYNC_READ;


	nfsreq->r_u.nfs->arg_nfs.arg_compound4.argarray.argarray_val = op;
	nfsreq->rtype = NFS_CALLBACK;
	nfsreq->r_u.nfs->cb_data.data = data;
	nfsreq->r_u.nfs->cb_data.arg_op_ctx = op_ctx;

	nfs_rpc_enqueue_req(nfsreq);
	res_ASYNCREAD4->status = NFS4_OK;
	resp->resop = NFS4_OP_ASYNC_READ;

	return res_ASYNCREAD4->status;
}

/**
 * @brief Free data allocated for ASYNC READ result.
 *
 *  Empty function as we are not allocating any memory for initial async read response
 *
 * @param[in,out] resp  Results fo nfs4_op
 *
 */
void nfs4_op_async_read_Free(nfs_resop4 *res)
{

		return;
}				/* nfs4_op_async_read_Free */







