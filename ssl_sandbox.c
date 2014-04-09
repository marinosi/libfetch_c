/*-
 * Copyright (c) 2014 Ilias Marinos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>

#include <sys/param.h>

#ifndef NO_SANDBOX
#include <sandbox.h>
/*#include <sandbox_rpc.h>*/
#endif

#ifdef WITH_SSL
#include <openssl/x509v3.h>
#endif

#include "fetch.h"
#include "common.h"
#include "ssl_sandbox_internal.h"

/* DPRINTF */
#ifdef DEBUG
#define DPRINTF(format, ...)				\
	fprintf(stderr, "%s [%d] " format "\n", 	\
	__FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define DPRINTF(...)
#endif

#define MMIN(a, b) ((a) < (b) ? (a) : (b))

#ifndef NO_SANDBOX

conn_t sconn; /* Global conn_t control block for the SSL sandbox */
int ssl_initialized = 0;

/* Operations */
typedef enum {
	SSL_INIT = 0,
	SSL_WRITE,
	SSL_READ,
	SSL_SHUTDOWN
} operation_t;

/* fetch sandbox control block */
struct sandbox_cb *fscb;

struct ssl_init_args {
	/*conn_t conn;*/
	struct url URL;
	int verbose;
} __packed;

struct ssl_read_args {
	size_t len;
} __packed;

struct ssl_write_args {
	size_t len;
	char wbuf[0];
} __packed;

struct ssl_req {
#define REQ_T_SSL_INIT    0x00
#define REQ_T_SSL_READ    0x01
#define REQ_T_SSL_WRITE   0x02
	uint8_t type;
	union {
		struct ssl_init_args iargs;
		struct ssl_read_args rargs;
		struct ssl_write_args wargs;
	};
} __packed;

struct ssl_rep {
#define REP_T_SSL_INIT  0x00
#define REP_T_SSL_READ  0x01
#define REP_T_SSL_WRITE 0x02
	uint8_t type;
	ssize_t	retval;
	ssize_t rbuf_len;
	char rbuf[0];
} __packed;

static void ssl_sandbox(void);
void
fetch_sandbox_init(void)
{

	fscb = calloc(1, sizeof(struct sandbox_cb));
	if(!fscb) {
		DPRINTF("[XXX] fscb wasn't initialized!");
		exit(-1);
	}
	sandbox_create(fscb, &ssl_sandbox);

}

void
fetch_sandbox_wait(void)
{
	wait(&rv);
	DPRINTF("Sandbox's exit status is %d", WEXITSTATUS(rv));
}


static int
fetch_ssl_insandbox(conn_t *conn, const struct url *URL, int verbose)
{
	struct ssl_req req;
	struct ssl_rep rep;
	struct iovec iov_req, iov_rep;
	int fdarray[1];
	size_t len;

	/* Clear out req */
	bzero(&req, sizeof(req));

	/* Pass needed data */
	fdarray[0] = dup(conn->sd); /* Get the file descriptor we need to pass */
	req.type = SSL_INIT;
	memmove(&req.iargs.URL, URL, sizeof(*URL));
	req.iargs.verbose = verbose;

	/* Update pointers to request and response structures */
	iov_req.iov_base = &req;
	iov_req.iov_len = sizeof(req);
	iov_rep.iov_base = &rep;
	iov_rep.iov_len = sizeof(rep);

	/*
	 * Ask the SSL sandbox to initialize SSL, by sending all the necessary info,
	 * including the actual fd for the established conn.
	 */
	if (host_rpc_rights(fscb, SSL_INIT, &iov_req, 1, fdarray, 1, &iov_rep,
		1, &len, NULL, NULL) < 0)
		err(-1, "host_rpc");

	if (len != sizeof(rep))
		errx(-1, "host_rpc");

	close(fdarray[0]);

	/* Upon success set SSL flag on */
	if (!rep.retval)
		conn->ssl_on = 1;

	return (rep.retval);
}

/* Called in parent to proxy the request though the sandbox */
/*
 * We do not need to pass the SSL handle as it already exists in the persistent
 * sandbox process from the SSL_INIT phase.
 */
static ssize_t
fetch_ssl_read_insandbox(char *buf, size_t rlen)
{
	struct ssl_req req;
	struct ssl_rep *rep;
	struct iovec iov_req, iov_rep;
	uint32_t opno, seqno;
	u_char *buffer;
	size_t len;

	/* Clear out req */
	bzero(&req, sizeof(req));

	/* Update the needed data */
	req.type = SSL_READ;
	req.rargs.len = rlen;

	seqno = 0;

	iov_req.iov_base = &req;
	iov_req.iov_len = sizeof(req);

	/*
	 * Ask the SSL sandbox to read rlen bytes from the SSL handle.
	 */
	if (host_sendrpc(fscb, SSL_READ, seqno, &iov_req, 1, NULL, 0) < 0)
		err(-1, "host_sendrpc");

	if (host_recvrpc(fscb, &opno, &seqno,  &buffer, &len) < 0) {
		if (errno == EPIPE) {
			DPRINTF("[XXX] EPIPE");
			exit(-1);
		} else if ( (opno != SSL_READ) || (seqno != 0)) {
			DPRINTF("[XXX] Wrong operation or sequence number!");
			exit(-1);
		} else {
			DPRINTF("[XXX] sandbox_recvrpc");
			err(-1, "sandbox_recvrpc");
		}
	}

	rep = (struct ssl_rep *) buffer;

	/* Clone the buffer from the RPC library */
	if(rep->rbuf_len > 0)
		memmove(buf, &rep->rbuf, rep->rbuf_len);


	free(buffer);
	return (rep->retval);
}

/* Called in parent to proxy the request though the sandbox */
/*
 * We do not need to pass the SSL handle as it already exists in the persistent
 * sandbox process from the SSL_INIT phase.
 */
static ssize_t
fetch_ssl_write_insandbox(char *buf, size_t rlen)
{
	struct ssl_req *req;
	struct ssl_rep *rep;
	struct iovec iov_req;
	uint32_t opno, seqno;
	u_char *buffer;
	size_t len, req_msg_size, ret;

	/* Clear out req */

	req_msg_size = sizeof(*req) + rlen - 1;
	req = calloc(1, req_msg_size);
	if (!req) {
		DPRINTF("[XXX] calloc() failed!");
		exit(-1);
	}
	req->type = SSL_WRITE;
	req->wargs.len = rlen;
	memmove(req->wargs.wbuf, buf, rlen);

	seqno = 0;

	iov_req.iov_base = req;
	iov_req.iov_len = sizeof(*req);

	/*
	 * Ask the SSL sandbox to read rlen bytes from the SSL handle.
	 */
	if (host_sendrpc(fscb, SSL_WRITE, seqno, &iov_req, 1, NULL, 0) < 0)
		err(-1, "host_sendrpc");

	if (host_recvrpc(fscb, &opno, &seqno,  &buffer, &len) < 0) {
		if (errno == EPIPE) {
			DPRINTF("[XXX] EPIPE");
			exit(-1);
		} else if ( (opno != SSL_WRITE) || (seqno != 0)) {
			DPRINTF("[XXX] Wrong operation or sequence number!");
			exit(-1);
		} else {
			DPRINTF("[XXX] sandbox_recvrpc");
			err(-1, "sandbox_recvrpc");
		}
	}
	
	if (len != sizeof(*rep)) {
		err(-1, "fetch_ssl_write_insandbox received msg len %zu", len);
		return (-1);
	}

	rep = (struct ssl_rep *) buffer;
	ret = rep->retval;

	free(buffer);
	return (ret);
}

static void
fetch_ssl_shutdown_insandbox(void)
{
	uint32_t seqno = 0;

	/*
	 * Ask the SSL sandbox to close the SSL handle and terminate.
	 * We do not expect anything back.
	 */
	if (host_sendrpc(fscb, SSL_SHUTDOWN, seqno, NULL, 0, NULL, 0) < 0)
		err(-1, "host_sendrpc");

	/* XXX IM: Wait for the sandbox to terminate? */

}

/* -------------------------------------------------------------------------- */
/* Called in sandbox and wraps the actual fetch_ssl */
static void
sandbox_fetch_ssl(struct sandbox_cb *scb, uint32_t opno, uint32_t seqno, char
	*buffer, size_t len, int *sockfd)
{
	struct ssl_req req;
	struct ssl_rep rep;
	struct iovec iov;

	if (len != sizeof(req))
		err(-1, "sandbox_fetch: len %zu", len);

	if (sockfd)
		sconn.sd = dup(*sockfd);

	/* Demangle data */
	memmove(&req, buffer, sizeof(req));

	/* Type should be set correctly */
	if (req.type != SSL_INIT)
		return;

	bzero(&rep, sizeof(rep));
	rep.retval = fetch_ssl(&sconn, &req.iargs.URL, req.iargs.verbose);
	iov.iov_base = &rep;
	iov.iov_len = sizeof(rep);

	if (sandbox_sendrpc(scb, opno, seqno, &iov, 1) < 0)
		err(-1, "sandbox_sendrpc");
}

/* Called in sandbox and wraps the actual fetch_ssl_read */
static void
sandbox_fetch_ssl_read(struct sandbox_cb *scb, uint32_t opno, uint32_t seqno, char
	*buffer, size_t len)
{
	struct ssl_req req;
	struct ssl_rep *rep;
	struct iovec iov;
	size_t rep_msg_size;
	ssize_t rlen;

	if (len != sizeof(req)) {
		err(-1, "sandbox_fetch_ssl_read: received msg len %zu", len);
		return;
	}

	/* Demangle data */
	memmove(&req, buffer, sizeof(req));

	/* Type should be set correctly */
	if (req.type != SSL_READ)
		return;


	rep_msg_size = sizeof(*rep);
	if(req.rargs.len)
		rep_msg_size += req.rargs.len;

	rep = malloc(rep_msg_size);
	if(!rep) {
		DPRINTF("[XXX] malloc() failed");
		exit(-1);
	}
	rep->type = SSL_READ;
	rlen = fetch_ssl_read(sconn.ssl, rep->rbuf, req.rargs.len);
	rep->retval = rep->rbuf_len = rlen;

	iov.iov_base = rep;
	iov.iov_len = rep_msg_size;
	if (sandbox_sendrpc(scb, opno, seqno, &iov, 1) < 0)
		err(-1, "sandbox_sendrpc");
	
	/* Release resources */
	free(rep);
}

/* Called in sandbox and wraps the actual fetch_ssl_read */
static void
sandbox_fetch_ssl_write(struct sandbox_cb *scb, uint32_t opno, uint32_t seqno, char
	*buffer, size_t len)
{
	struct ssl_req *req;
	struct ssl_rep rep;
	struct iovec iov;

	if (len < sizeof(*req)) {
		err(-1, "sandbox_fetch_ssl_read: received msg len %zu", len);
		return;
	}

	req = (struct ssl_req *) buffer;
	if(req->type != SSL_WRITE)
		return;

	rep.retval = fetch_ssl_write(sconn.ssl, req->wargs.wbuf, req->wargs.len);

	iov.iov_base = &rep;
	iov.iov_len = sizeof(rep);
	if (sandbox_sendrpc(scb, opno, seqno, &iov, 1) < 0)
		err(-1, "sandbox_sendrpc");
}

static void
ssl_sandbox(void)
{
	uint32_t opno, seqno;
	u_char *buffer;
	size_t len;
	int fdarray[1], fdcount; /* We expect a fd for SSL_INIT op */
	int *fdp;
	int ssl_shutdown = 0;

	DPRINTF("===> In ssl_sandbox()");

	ssl_initialized = 0;
	while (!ssl_shutdown) {
		/* No SSL initialized on top of established conn */
		if (!ssl_initialized) {
			DPRINTF("\tSSL not initialized!");
			fdp = fdarray;
			fdcount = 1; /* we are waiting for a fd */
		}
		else {
			/*DPRINTF("\tSSL is already initialized!");*/
			fdp = NULL;
			fdcount = 0; /* SSL is already initialized -- no need for fd */
		}

		/* Get the output fd and URL from parent */
		if (sandbox_recvrpc_rights(fscb, &opno, &seqno,  &buffer, &len, fdp,
			&fdcount) < 0) {
			if (errno == EPIPE) {
				DPRINTF("[XXX] EPIPE");
				exit(-1);
			}
			else {
				DPRINTF("[XXX] sandbox_recvrpc");
				err(-1, "sandbox_recvrpc");
			}
		}

		switch(opno) {
		case SSL_INIT:
			/* fetch the url and return */
			DPRINTF("[OP] SSL INITIALIZATION");
			sandbox_fetch_ssl(fscb, opno, seqno, (char *)buffer, len,
				&fdarray[0]);
			close(fdarray[0]);
			ssl_initialized = 1;
			break;
		case SSL_READ:
			/*DPRINTF("[OP] SSL READ");*/
			sandbox_fetch_ssl_read(fscb, opno, seqno, (char *) buffer, len);
			break;
		case SSL_WRITE:
			/*DPRINTF("[OP] SSL WRITE");*/
			sandbox_fetch_ssl_write(fscb, opno, seqno, (char *) buffer, len);
			break;
		case SSL_SHUTDOWN:
			DPRINTF("[OP] SSL SHUTDOWN");
			fetch_ssl_shutdown(&sconn);
			ssl_shutdown = 1;
			break;
		default:
			errx(-1, "sandbox_main: unknown operation %d", opno);
		}
	}

	/* Free buffers */
	free(buffer);

	/* exit */
	exit(0);
}

#endif

int
fetch_ssl_wrapper(conn_t *conn, const struct url *URL, int verbose)
{
#ifdef NO_SANDBOX
	return (fetch_ssl(conn, URL, verbose));
#else
	fetch_sandbox_init();
	return (fetch_ssl_insandbox(conn, URL, verbose));
#endif
}

ssize_t
fetch_ssl_read_wrapper(SSL *ssl, char *buf, size_t buflen)
{
#ifdef NO_SANDBOX
	return (fetch_ssl_read(ssl, buf, buflen));
#else
	return (fetch_ssl_read_insandbox(buf, buflen));
#endif
}

ssize_t
fetch_ssl_write_wrapper(SSL *ssl, char *buf, size_t buflen)
{
#ifdef NO_SANDBOX
	return (fetch_ssl_write(ssl, buf, buflen));
#else
	return (fetch_ssl_write_insandbox(buf, buflen));
#endif
}

void
fetch_ssl_shutdown_wrapper(conn_t *conn)
{
#ifdef NO_SANDBOX
	fetch_ssl_shutdown(conn);
#else
	fetch_ssl_shutdown_insandbox();
	conn->ssl_on = 0;
#endif
}
