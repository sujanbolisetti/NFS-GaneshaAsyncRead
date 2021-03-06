/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "nfs-ganesha/src/Protocols/XDR/nfsv41.h"
#include <stdio.h>
#include <stdlib.h>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef SIG_PF
#define SIG_PF void(*)(int)
#endif
#ifndef _AUTH_SYS_DEFINE_FOR_NFSv41
#define _AUTH_SYS_DEFINE_FOR_NFSv41
#include <rpc/auth_sys.h>
typedef struct authsys_parms authsys_parms;
#endif /* _AUTH_SYS_DEFINE_FOR_NFSv41 */
/*
 * LAYOUT4_OSD2_OBJECTS loc_body description
 * is in a separate .x file
 */

/*
 * LAYOUT4_BLOCK_VOLUME loc_body description
 * is in a separate .x file
 */


 /* layouttype4 specific data */

/*
 * REQUIRED Attributes
 */
/* new to NFSV4.1 */
/*
 * RECOMMENDED Attributes
 */

/* new to NFSV4.1 */


/* Input for computing subkeys */


/* Input for computing smt_hmac */


/* SSV GSS PerMsgToken token */


/* Input for computing ssct_encr_data and ssct_hmac */


/* SSV GSS SealedMessage token */



/* Encoded in the loh_body field of data type layouthint4: */




/*
 * Encoded in the da_addr_body field of
 * data type device_addr4:
 */


/*
 * Encoded in the loc_body field of
 * data type layout_content4:
 */

/*
 * Encoded in the lou_body field of data type layoutupdate4:
 *      Nothing. lou_body is a zero length array of bytes.
 */

/*
 * Encoded in the lrf_body field of
 * data type layoutreturn_file4:
 *      Nothing. lrf_body is a zero length array of bytes.
 */


/* new operations for NFSv4.1 */


/* Callback operations new to NFSv4.1 */

static void
nfs4_program_4(struct svc_req *rqstp, register SVCXPRT *transp)
{
	union {
		COMPOUND4args nfsproc4_compound_4_arg;
	} argument;
	char *result;
	xdrproc_t _xdr_argument, _xdr_result;
	char *(*local)(char *, struct svc_req *);

	switch (rqstp->rq_proc) {
	case NFSPROC4_NULL:
		_xdr_argument = (xdrproc_t) xdr_void;
		_xdr_result = (xdrproc_t) xdr_void;
		local = (char *(*)(char *, struct svc_req *)) nfsproc4_null_4_svc;
		break;

	case NFSPROC4_COMPOUND:
		_xdr_argument = (xdrproc_t) xdr_COMPOUND4args;
		_xdr_result = (xdrproc_t) xdr_COMPOUND4res;
		local = (char *(*)(char *, struct svc_req *)) nfsproc4_compound_4_svc;
		break;

	default:
		svcerr_noproc (transp);
		return;
	}
	memset ((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		svcerr_decode (transp);
		return;
	}
	result = (*local)((char *)&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, (xdrproc_t) _xdr_result, result)) {
		svcerr_systemerr (transp);
	}
	if (!svc_freeargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		fprintf (stderr, "%s", "unable to free arguments");
		exit (1);
	}
	return;
}

static void
nfs4_callback_1(struct svc_req *rqstp, register SVCXPRT *transp)
{
	union {
		CB_COMPOUND4args cb_compound_1_arg;
	} argument;
	char *result;
	xdrproc_t _xdr_argument, _xdr_result;
	char *(*local)(char *, struct svc_req *);

	switch (rqstp->rq_proc) {
	case CB_NULL:
		_xdr_argument = (xdrproc_t) xdr_void;
		_xdr_result = (xdrproc_t) xdr_void;
		local = (char *(*)(char *, struct svc_req *)) cb_null_1_svc;
		break;

	case CB_COMPOUND:
		_xdr_argument = (xdrproc_t) xdr_CB_COMPOUND4args;
		_xdr_result = (xdrproc_t) xdr_CB_COMPOUND4res;
		local = (char *(*)(char *, struct svc_req *)) cb_compound_1_svc;
		break;

	default:
		svcerr_noproc (transp);
		return;
	}
	memset ((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		svcerr_decode (transp);
		return;
	}
	result = (*local)((char *)&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, (xdrproc_t) _xdr_result, result)) {
		svcerr_systemerr (transp);
	}
	if (!svc_freeargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		fprintf (stderr, "%s", "unable to free arguments");
		exit (1);
	}
	return;
}

int
main (int argc, char **argv)
{
	register SVCXPRT *transp;

	pmap_unset (NFS4_PROGRAM, NFS_V4);
	pmap_unset (NFS4_CALLBACK, NFS_CB);

	transp = svcudp_create(RPC_ANYSOCK);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create udp service.");
		exit(1);
	}
	if (!svc_register(transp, NFS4_PROGRAM, NFS_V4, nfs4_program_4, IPPROTO_UDP)) {
		fprintf (stderr, "%s", "unable to register (NFS4_PROGRAM, NFS_V4, udp).");
		exit(1);
	}
	if (!svc_register(transp, NFS4_CALLBACK, NFS_CB, nfs4_callback_1, IPPROTO_UDP)) {
		fprintf (stderr, "%s", "unable to register (NFS4_CALLBACK, NFS_CB, udp).");
		exit(1);
	}

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create tcp service.");
		exit(1);
	}
	if (!svc_register(transp, NFS4_PROGRAM, NFS_V4, nfs4_program_4, IPPROTO_TCP)) {
		fprintf (stderr, "%s", "unable to register (NFS4_PROGRAM, NFS_V4, tcp).");
		exit(1);
	}
	if (!svc_register(transp, NFS4_CALLBACK, NFS_CB, nfs4_callback_1, IPPROTO_TCP)) {
		fprintf (stderr, "%s", "unable to register (NFS4_CALLBACK, NFS_CB, tcp).");
		exit(1);
	}

	svc_run ();
	fprintf (stderr, "%s", "svc_run returned");
	exit (1);
	/* NOTREACHED */
}
