/*
   Unix SMB/CIFS implementation.
   Main SMB server routines
   Copyright (C) Andrew Tridgell		1992-1998
   Copyright (C) Martin Pool			2002
   Copyright (C) Jelmer Vernooij		2002-2003
   Copyright (C) Volker Lendecke		1993-2007
   Copyright (C) Jeremy Allison			1993-2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/filesys.h"
#include "lib/util/server_id.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "registry/reg_init_full.h"
#include "libcli/auth/schannel.h"
#include "secrets.h"
#include "../lib/util/memcache.h"
#include "rpc_server/rpc_service_setup.h"
#include "rpc_server/rpc_config.h"
#include "passdb.h"
#include "auth.h"
#include "messages.h"
#include "smbprofile.h"
#include "lib/id_cache.h"
#include "lib/param/param.h"
#include "../lib/util/pidfile.h"
#include "lib/smbd_shim.h"
#include "scavenger.h"
#include "locking/leases_db.h"
#include "smbd/notifyd/notifyd.h"
#include "smbd/smbd_cleanupd.h"
#include "lib/util/sys_rw.h"
#include "g_lock.h"
#include "../librpc/gen_ndr/srv_dfs.h"
#include "../librpc/gen_ndr/srv_dssetup.h"
#include "../librpc/gen_ndr/srv_echo.h"
#include "../librpc/gen_ndr/srv_eventlog.h"
#include "../librpc/gen_ndr/srv_initshutdown.h"
#include "../librpc/gen_ndr/srv_lsa.h"
#include "../librpc/gen_ndr/srv_netlogon.h"
#include "../librpc/gen_ndr/srv_ntsvcs.h"
#include "../librpc/gen_ndr/srv_samr.h"
#include "../librpc/gen_ndr/srv_spoolss.h"
#include "../librpc/gen_ndr/srv_srvsvc.h"
#include "../librpc/gen_ndr/srv_svcctl.h"
#include "../librpc/gen_ndr/srv_winreg.h"
#include "../librpc/gen_ndr/srv_wkssvc.h"
#include "printing.h"
#include "libcli/auth/netlogon_creds_cli.h"
#include "smbserver.h"

#define PROCS_NAME	"smbd"
#define SHARE_NAME 	"share"

#define CHECK_ON_COMPILE(condition) ((void)sizeof(char[1 - 2*!(condition)]))
#define itoa(a) ((a) < 0xa?'0'+(a):'A' + (a-0xa))

static int initial_resource(void);
static void release_resource(void);
static void smb_server_exit_cleanly(const char *const explanation);
static bool smbd_close_listen_socket(struct smbd_parent_context *parent);

extern void build_options(bool screen);
extern void smb_process(struct tevent_context *ev_ctx, struct messaging_context *msg_ctx, int sock_fd, bool interactive);

static struct smb_callback{
	FN_ON_START on_start;
	FN_ON_CONNECT on_connect;
	FN_ON_DISCONNECT on_disconnect;
	FN_ON_EXIT on_exit;
}Callback;

static struct smb_userinfo{
	struct smb_userinfo *prev, *next;
	char *usr;
	char *pwd;
}*accounts = NULL;

struct smbd_open_socket {
	struct smbd_open_socket *prev, *next;
	struct smbd_parent_context *parent;
	int fd;
	struct tevent_fd *fde;
};

const struct smbd_shim smbd_shim_fns =
{
	.cancel_pending_lock_requests_by_fid = smbd_cancel_pending_lock_requests_by_fid,
	.send_stat_cache_delete_message = smbd_send_stat_cache_delete_message,
	.change_to_root_user = smbd_change_to_root_user,
	.become_authenticated_pipe_user = smbd_become_authenticated_pipe_user,
	.unbecome_authenticated_pipe_user = smbd_unbecome_authenticated_pipe_user,

	.contend_level2_oplocks_begin = smbd_contend_level2_oplocks_begin,
	.contend_level2_oplocks_end = smbd_contend_level2_oplocks_end,

	.become_root = NULL,
	.unbecome_root = NULL,

	.exit_server = smbd_exit_server,
	.exit_server_cleanly = smb_server_exit_cleanly,
};

static struct files_struct *log_writeable_file_fn(struct files_struct *fsp, void *private_data)
{
	bool *found = (bool *)private_data;
	char *path;

	if (!fsp->can_write) {
		return NULL;
	}
	if (!(*found)) {
		DEBUG(0, ("Writable files open at exit:\n"));
		*found = true;
	}

	path = talloc_asprintf(talloc_tos(), "%s/%s", fsp->conn->connectpath, smb_fname_str_dbg(fsp->fsp_name));
	if (path == NULL) {
		DEBUGADD(0, ("<NOMEM>\n"));
	}

	DEBUGADD(0, ("%s\n", path));

	TALLOC_FREE(path);
	return NULL;
}

static void disconnect_smb_client(struct smbXsrv_client *client)
{
	struct smbXsrv_connection *xconn = NULL;
	struct smbXsrv_connection *xconn_next = NULL;
	struct smbd_server_connection *sconn = NULL;
	struct messaging_context *msg_ctx = global_messaging_context();


	sconn = client->sconn;
	/*
	 * Here we typically have just one connection
	 */
	xconn = client->connections;


	change_to_root_user();

	/*
	 * Here we typically have just one connection
	 */
	for (; xconn != NULL; xconn = xconn_next) {
		xconn_next = xconn->next;
		DLIST_REMOVE(client->connections, xconn);

		xconn->transport.status = NT_STATUS_LOCAL_DISCONNECT;

		TALLOC_FREE(xconn);
		DO_PROFILE_INC(disconnect);
	}

	change_to_root_user();

	if (sconn != NULL) {
		if (lp_log_writeable_files_on_exit()) {
			bool found = false;
			files_forall(sconn, log_writeable_file_fn, &found);
		}
	}

	/*
	 * Note: this is a no-op for smb2 as
	 * conn->tcon_table is empty
	 */
	NTSTATUS status = smb1srv_tcon_disconnect_all(client);
	if (!NT_STATUS_IS_OK(status)) {
		// DEBUG(0,("Server exit (%s)\n",
		// 	(reason ? reason : "normal exit")));
		DEBUG(0, ("exit_server_common: "
			  "smb1srv_tcon_disconnect_all() failed (%s) - "
			  "triggering cleanup\n", nt_errstr(status)));
	}

	status = smbXsrv_session_logoff_all(client);
	if (!NT_STATUS_IS_OK(status)) {
		// DEBUG(0,("Server exit (%s)\n",
		// 	(reason ? reason : "normal exit")));
		DEBUG(0, ("exit_server_common: "
			  "smbXsrv_session_logoff_all() failed (%s) - "
			  "triggering cleanup\n", nt_errstr(status)));
	}

	/*
	 * we need to force the order of freeing the following,
	 * because smbd_msg_ctx is not a talloc child of smbd_server_conn.
	 */
	TALLOC_FREE(client->sconn);
	sconn = NULL;
	xconn = NULL;
}

static void msg_exit_server(struct messaging_context *msg,
			    void *private_data,
			    uint32_t msg_type,
			    struct server_id server_id,
			    DATA_BLOB *data)
{
	DEBUG(3, ("got a SHUTDOWN message\n"));
	exit_server_cleanly(NULL);
}

/*
 * Parent smbd process sets its own debug level first and then
 * sends a message to all the smbd children to adjust their debug
 * level to that of the parent.
 */

static void smbd_msg_debug(struct messaging_context *msg_ctx,
			   void *private_data,
			   uint32_t msg_type,
			   struct server_id server_id,
			   DATA_BLOB *data)
{
	debug_message(msg_ctx, private_data, MSG_DEBUG, server_id, data);

	// messaging_send_to_children(msg_ctx, MSG_DEBUG, data);
}

static void smb_tell_num_children(struct messaging_context *ctx, void *data,
				  uint32_t msg_type, struct server_id srv_id,
				  DATA_BLOB *msg_data)
{
	uint8_t buf[sizeof(uint32_t)];

	if (am_parent) {
		SIVAL(buf, 0, am_parent->num_children);
		messaging_send_buf(ctx, srv_id, MSG_SMB_NUM_CHILDREN,
				   buf, sizeof(buf));
	}
}

static void notifyd_stopped(struct tevent_req *req);

static struct tevent_req *notifyd_req(struct messaging_context *msg_ctx,
				      struct tevent_context *ev)
{
	struct tevent_req *req;
	sys_notify_watch_fn sys_notify_watch = NULL;
	struct sys_notify_context *sys_notify_ctx = NULL;

	if (lp_kernel_change_notify()) {

#ifdef HAVE_INOTIFY
		if (lp_parm_bool(-1, "notify", "inotify", true)) {
			sys_notify_watch = inotify_watch;
		}
#endif

#ifdef HAVE_FAM
		if (lp_parm_bool(-1, "notify", "fam",
				 (sys_notify_watch == NULL))) {
			sys_notify_watch = fam_watch;
		}
#endif
	}

	if (sys_notify_watch != NULL) {
		sys_notify_ctx = sys_notify_context_create(msg_ctx, ev);
		if (sys_notify_ctx == NULL) {
			return NULL;
		}
	}

	req = notifyd_send(msg_ctx, ev, msg_ctx, NULL,
			   sys_notify_watch, sys_notify_ctx);
	if (req == NULL) {
		TALLOC_FREE(sys_notify_ctx);
		return NULL;
	}
	tevent_req_set_callback(req, notifyd_stopped, msg_ctx);

	return req;
}

static void notifyd_stopped(struct tevent_req *req)
{
	int ret;

	ret = notifyd_recv(req);
	TALLOC_FREE(req);
	DEBUG(1, ("notifyd stopped: %s\n", strerror(ret)));
}

static bool smbd_notifyd_init(struct messaging_context *msg, bool interactive,
			      struct server_id *ppid)
{
	struct tevent_context *ev = messaging_tevent_context(msg);
	struct tevent_req *req;
	pid_t pid;
	NTSTATUS status;
	bool ok;

	req = notifyd_req(msg, ev);
	return (req != NULL);
}

static void notifyd_init_trigger(struct tevent_req *req);

struct notifyd_init_state {
	bool ok;
	struct tevent_context *ev;
	struct messaging_context *msg;
	struct server_id *ppid;
};

static bool notifyd_init_recv(struct tevent_req *req)
{
	struct notifyd_init_state *state = tevent_req_data(
		req, struct notifyd_init_state);

	return state->ok;
}

static void notifyd_started(struct tevent_req *req)
{
	bool ok;

	ok = notifyd_init_recv(req);
	TALLOC_FREE(req);
	if (!ok) {
		DBG_ERR("Failed to restart notifyd, giving up\n");
		return;
	}
}

static void cleanupd_stopped(struct tevent_req *req);

static bool cleanupd_init(struct messaging_context *msg, bool interactive,
			  struct server_id *ppid)
{
	struct tevent_context *ev = messaging_tevent_context(msg);
	struct server_id parent_id = messaging_server_id(msg);
	struct tevent_req *req;
	pid_t pid;
	NTSTATUS status;
	ssize_t rwret;
	int ret;
	bool ok;
	char c;
	int up_pipe[2];

	req = smbd_cleanupd_send(msg, ev, msg, parent_id.pid);
	*ppid = messaging_server_id(msg);
	return (req != NULL);
}

static void cleanupd_stopped(struct tevent_req *req)
{
	NTSTATUS status;

	status = smbd_cleanupd_recv(req);
	DBG_WARNING("cleanupd stopped: %s\n", nt_errstr(status));
}

/****************************************************************************
 Have we reached the process limit ?
****************************************************************************/

static bool allowable_number_of_smbd_processes(struct smbd_parent_context *parent)
{
	int max_processes = lp_max_smbd_processes();

	if (!max_processes)
		return True;

	return parent->num_children < max_processes;
}

static void smbd_open_socket_close_fn(struct tevent_context *ev,
				      struct tevent_fd *fde,
				      int fd,
				      void *private_data)
{
	/* this might be the socket_wrapper swrap_close() */
	close(fd);
}

static void smbd_accept_connection(struct tevent_context *ev,
				   struct tevent_fd *fde,
				   uint16_t flags,
				   void *private_data)
{
	struct smbd_open_socket *s = talloc_get_type_abort(private_data,
				     struct smbd_open_socket);
	struct messaging_context *msg_ctx = s->parent->msg_ctx;
	struct sockaddr_storage addr;
	socklen_t in_addrlen = sizeof(addr);
	int fd;
	pid_t pid = 0;

	fd = accept(s->fd, (struct sockaddr *)(void *)&addr,&in_addrlen);
	if (fd == -1 && errno == EINTR)
		return;

	if (fd == -1) {
		DEBUG(0,("accept: %s\n",
			 strerror(errno)));
		return;
	}
	smb_set_close_on_exec(fd);

	// close listening sockets
	// smbd_close_listen_socket(s->parent);

	smb_process(ev, msg_ctx, fd, true);
}

static bool smbd_close_listen_socket(struct smbd_parent_context *parent)
{
	struct smbd_open_socket *s = parent->sockets;
	for(; s != NULL; ) {
		DLIST_REMOVE(parent->sockets, s);

		talloc_free(s->fde);
		talloc_free(s);
		
		s = parent->sockets;
	}

	return true;
}

static bool smbd_open_one_socket(struct smbd_parent_context *parent,
				 struct tevent_context *ev_ctx,
				 const struct sockaddr_storage *ifss,
				 uint16_t port)
{
	struct smbd_open_socket *s;

	s = talloc(parent, struct smbd_open_socket);
	if (!s) {
		return false;
	}

	s->parent = parent;
	s->fd = open_socket_in(SOCK_STREAM,
			       port,
			       parent->sockets == NULL ? 0 : 2,
			       ifss,
			       true);
	if (s->fd == -1) {
		DEBUG(0,("smbd_open_one_socket: open_socket_in: "
			"%s\n", strerror(errno)));
		TALLOC_FREE(s);
		return false;
	}

	/* ready to listen */
	set_socket_options(s->fd, "SO_KEEPALIVE");
	set_socket_options(s->fd, lp_socket_options());

	/* Set server socket to
	 * non-blocking for the accept. */
	set_blocking(s->fd, False);

	if (listen(s->fd, SMBD_LISTEN_BACKLOG) == -1) {
		DEBUG(0,("smbd_open_one_socket: listen: "
			"%s\n", strerror(errno)));
			close(s->fd);
		TALLOC_FREE(s);
		return false;
	}

	s->fde = tevent_add_fd(ev_ctx,
			       s,
			       s->fd, TEVENT_FD_READ,
			       smbd_accept_connection,
			       s);
	if (!s->fde) {
		DEBUG(0,("smbd_open_one_socket: "
			 "tevent_add_fd: %s\n",
			 strerror(errno)));
		close(s->fd);
		TALLOC_FREE(s);
		return false;
	}
	tevent_fd_set_close_fn(s->fde, smbd_open_socket_close_fn);

	DLIST_ADD_END(parent->sockets, s);

	return true;
}

/****************************************************************************
 Open the socket communication.
****************************************************************************/

static bool open_sockets_smbd(struct smbd_parent_context *parent,
			      struct tevent_context *ev_ctx,
			      struct messaging_context *msg_ctx,
			      const char *smb_ports)
{
	int i,j;
	const char **ports;
	unsigned dns_port = 0;

// #ifdef HAVE_ATEXIT
// 	atexit(killkids);
// #endif

	/* Stop zombies */
	// smbd_setup_sig_chld_handler(parent);

	ports = lp_smb_ports();

	/* use a reasonable default set of ports - listing on 445 and 139 */
	if (smb_ports) {
		char **l;
		l = str_list_make_v3(talloc_tos(), smb_ports, NULL);
		ports = discard_const_p(const char *, l);
	}

	for (j = 0; ports && ports[j]; j++) {
		unsigned port = atoi(ports[j]);

		if (port == 0 || port > 0xffff) {
			exit_server_cleanly("Invalid port in the config or on " "the commandline specified!");
		}
	}

	/* Just bind to 0.0.0.0 - accept connections from anywhere. */
	// const char *sock_addr;
	// char *sock_tok;
	// const char *sock_ptr;

// #if HAVE_IPV6
// 	sock_addr = "::,0.0.0.0";
// #else
// 	sock_addr = "0.0.0.0";
// #endif

	// for (sock_ptr=sock_addr; next_token_talloc(talloc_tos(), &sock_ptr, &sock_tok, " \t,"); ) {
	char *sock_tok;
	unsigned int port;
	char addr[INET6_ADDRSTRLEN];
	int num_interfaces = iface_count();
	for (i = 0; i < num_interfaces; i++) {

		struct interface *iface = get_interface(i);
		if (!iface){
			continue;
		}
		
		sock_tok = print_sockaddr(addr, sizeof(addr), &(iface->ip));

		for (j = 0; ports && ports[j]; j++) {
			struct sockaddr_storage ss;
			port = atoi(ports[j]);

			/* Keep the first port for mDNS service
			 * registration.
			 */
			if (dns_port == 0) {
				dns_port = port;
			}

			/* open an incoming socket */
			if (!interpret_string_addr(&ss, sock_tok, AI_NUMERICHOST|AI_PASSIVE) || ss.ss_family == AF_INET6) {
				continue;
			}

			/*
			 * If we fail to open any sockets
			 * in this loop the parent-sockets == NULL
			 * case below will prevent us from starting.
			 */
			if(smbd_open_one_socket(parent, ev_ctx, &ss, port)) {
				break;  //open one port only
			}
		}
	}

	if (parent->sockets == NULL) {
		DEBUG(0,("open_sockets_smbd: No sockets available to bind to.\n"));
		return false;
	}

	if(parent->on_start) {
		parent->on_start(sock_tok, port);
	}

	return true;
}

struct smbd_parent_tevent_trace_state {
	TALLOC_CTX *frame;
};

static void smbd_parent_tevent_trace_callback(enum tevent_trace_point point,
					      void *private_data)
{
	struct smbd_parent_tevent_trace_state *state =
		(struct smbd_parent_tevent_trace_state *)private_data;

	switch (point) {
	case TEVENT_TRACE_BEFORE_WAIT:
		break;
	case TEVENT_TRACE_AFTER_WAIT:
		break;
	case TEVENT_TRACE_BEFORE_LOOP_ONCE:
		TALLOC_FREE(state->frame);
		state->frame = talloc_stackframe();
		break;
	case TEVENT_TRACE_AFTER_LOOP_ONCE:
		TALLOC_FREE(state->frame);
		break;
	}

	errno = 0;
}

static int smb_server_loop(struct tevent_context *ev_ctx, struct smbd_parent_context *parent)
{
	struct smbd_parent_tevent_trace_state trace_state = {
		.frame = NULL,
	};
	int ret = 0;

	tevent_set_trace_callback(ev_ctx, smbd_parent_tevent_trace_callback, &trace_state);

	/* now accept incoming connections - forking a new process
	   for each incoming connection */
	DEBUG(2,("waiting for connections\n"));

	parent->exit_flag = false;

	while(!parent->exit_flag) {
		ret = tevent_loop_once(ev_ctx);
		if (ret != 0) {
			DEBUG(0, ("tevent_loop_once failed: %d, %s, exiting\n", ret, strerror(errno)));
		}
	}

	TALLOC_FREE(trace_state.frame);

	return ret;
}


/****************************************************************************
 Initialise connect, service and file structs.
****************************************************************************/

static bool init_structs(void )
{
	/*
	 * Set the machine NETBIOS name if not already
	 * set from the config file.
	 */

	if (!init_names())
		return False;

	if (!secrets_init())
		return False;

	return True;
}

static void smbd_parent_sig_term_handler(struct tevent_context *ev,
					 struct tevent_signal *se,
					 int signum,
					 int count,
					 void *siginfo,
					 void *private_data)
{
	exit_server_cleanly("termination signal");
}

static void smbd_parent_sig_hup_handler(struct tevent_context *ev,
					struct tevent_signal *se,
					int signum,
					int count,
					void *siginfo,
					void *private_data)
{
	struct smbd_parent_context *parent =
		talloc_get_type_abort(private_data,
		struct smbd_parent_context);

	change_to_root_user();
	DEBUG(1,("parent: Reloading services after SIGHUP\n"));
	reload_services(NULL, NULL, false);

	// printing_subsystem_update(parent->ev_ctx, parent->msg_ctx, true);
}

struct smbd_claim_version_state {
	TALLOC_CTX *mem_ctx;
	char *version;
};

static void smbd_claim_version_parser(const struct g_lock_rec *locks,
				      size_t num_locks,
				      const uint8_t *data,
				      size_t datalen,
				      void *private_data)
{
	struct smbd_claim_version_state *state = private_data;

	if (datalen == 0) {
		state->version = NULL;
		return;
	}
	if (data[datalen-1] != '\0') {
		DBG_WARNING("Invalid samba version\n");
		dump_data(DBGLVL_WARNING, data, datalen);
		state->version = NULL;
		return;
	}
	state->version = talloc_strdup(state->mem_ctx, (const char *)data);
}

static NTSTATUS smbd_claim_version(struct messaging_context *msg,
				   const char *version)
{
	const char *name = "samba_version_string";
	struct smbd_claim_version_state state;
	struct g_lock_ctx *ctx;
	NTSTATUS status;

	ctx = g_lock_ctx_init(msg, msg);
	if (ctx == NULL) {
		DBG_WARNING("g_lock_ctx_init failed\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	status = g_lock_lock(ctx, string_term_tdb_data(name), G_LOCK_READ,
			     (struct timeval) { .tv_sec = 60 });
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("g_lock_lock(G_LOCK_READ) failed: %s\n",
			    nt_errstr(status));
		TALLOC_FREE(ctx);
		return status;
	}

	state = (struct smbd_claim_version_state) { .mem_ctx = ctx };

	status = g_lock_dump(ctx, string_term_tdb_data(name),
			     smbd_claim_version_parser, &state);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		DBG_ERR("Could not read samba_version_string\n");
		g_lock_unlock(ctx, string_term_tdb_data(name));
		TALLOC_FREE(ctx);
		return status;
	}

	if ((state.version != NULL) && (strcmp(version, state.version) == 0)) {
		/*
		 * Leave the read lock for us around. Someone else already
		 * set the version correctly
		 */
		TALLOC_FREE(ctx);
		return NT_STATUS_OK;
	}

	status = g_lock_lock(ctx, string_term_tdb_data(name), G_LOCK_WRITE,
			     (struct timeval) { .tv_sec = 60 });
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("g_lock_lock(G_LOCK_WRITE) failed: %s\n",
			    nt_errstr(status));
		DBG_ERR("smbd %s already running, refusing to start "
			"version %s\n", state.version, version);
		TALLOC_FREE(ctx);
		return NT_STATUS_SXS_VERSION_CONFLICT;
	}

	status = g_lock_write_data(ctx, string_term_tdb_data(name),
				   (const uint8_t *)version,
				   strlen(version)+1);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("g_lock_write_data failed: %s\n",
			    nt_errstr(status));
		TALLOC_FREE(ctx);
		return status;
	}

	status = g_lock_lock(ctx, string_term_tdb_data(name), G_LOCK_READ,
			     (struct timeval) { .tv_sec = 60 });
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("g_lock_lock(G_LOCK_READ) failed: %s\n",
			    nt_errstr(status));
		TALLOC_FREE(ctx);
		return status;
	}

	/*
	 * Leave "ctx" dangling so that g_lock.tdb keeps opened.
	 */
	return NT_STATUS_OK;
}


int set_smb_password(const char *username, const char *password)
{
	TALLOC_CTX *frame = NULL;
	int ret = 0;
	char *err = NULL, *msg = NULL;

	frame = talloc_stackframe();
	if (!frame) {
		return -1;
	}

	NTSTATUS status;
	int flags = LOCAL_ADD_USER | LOCAL_SET_PASSWORD;
	status = local_password_change(username, flags, password, &err, &msg);
	if (!NT_STATUS_IS_OK(status)) {
		ret = -1;
		goto done;
	}

done:
	SAFE_FREE(err);
	SAFE_FREE(msg);
	TALLOC_FREE(frame);
	return ret;
}

int del_smb_password(const char *username)
{
	TALLOC_CTX *frame = NULL;
	int ret = 0;
	char *err = NULL, *msg = NULL;

	frame = talloc_stackframe();
	if (!frame) {
		return -1;
	}

	NTSTATUS status;
	int flags = LOCAL_DELETE_USER;
	status = local_password_change(username, flags, NULL, &err, &msg);
	if (!NT_STATUS_IS_OK(status)) {
		ret = -1;
		goto done;
	}

done:
	SAFE_FREE(err);
	SAFE_FREE(msg);
	TALLOC_FREE(frame);
	return ret;
}

int start_smb_server()
{
	//be sure configured correctly
	CHECK_ON_COMPILE(sizeof(uint16_t) == 2);
	CHECK_ON_COMPILE(sizeof(uint32_t) == 4);

	if (am_parent && !am_parent->exit_flag) {
		return 0;
	}

	//talloc_enable_null_tracking();
	talloc_disable_null_tracking();    //for thread-safe

	/* make sure we always have a valid stackframe */
	TALLOC_CTX *frame = talloc_stackframe();

	if(initial_resource()) {
		return -1;
	}

	//from now on, must call back if seted.
	am_parent->on_start = Callback.on_start;
	am_parent->on_connect = Callback.on_connect;
	am_parent->on_disconnect = Callback.on_disconnect;
	am_parent->on_exit = Callback.on_exit;

	if(!open_sockets_smbd(am_parent, am_parent->ev_ctx, am_parent->msg_ctx, NULL)) {
		release_resource();
		TALLOC_FREE(frame);
		return -1;
	}

	struct smb_userinfo *account = accounts;
	for (; account != NULL; ) {
		set_smb_password(account->usr, account->pwd);
		account = account->next;
	}

	int ret = smb_server_loop(am_parent->ev_ctx, am_parent);

	if(am_parent->on_exit != NULL) {
		am_parent->on_exit();
    }

	release_resource();
	TALLOC_FREE(frame);
	return ret;
}

int stop_smb_server(void)
{
	if(am_parent && !am_parent->exit_flag) {
		//kill(getpid(), SIGTERM);
		kill(getpid(), SIGUSR2);
	}
	return 0;
}

int initial_resource()
{
	int ret = 0;
	struct tevent_context *ev_ctx = NULL;
	struct messaging_context *msg_ctx = NULL;
	struct server_id main_server_id = {0};

	setup_logging(PROCS_NAME, DEBUG_FILE);

	smb_init_locale();

	set_smbd_shim(&smbd_shim_fns);

	smbd_init_globals();

	TimeInit();

	set_remote_machine_name(PROCS_NAME, False);

	if (DEBUGLEVEL >= 9) {
		talloc_enable_leak_report();
	}

	/*
	 * We want to die early if we can't open /dev/urandom
	 */
	generate_random_buffer(NULL, 0);

	/* get initial effective uid and gid */
	sec_init();

	fault_setup();
	// dump_core_setup(PROCS_NAME, filename);

	/* we are never interested in SIGPIPE */
	BlockSignals(True,SIGPIPE);

#if defined(SIGFPE)
	/* we are never interested in SIGFPE */
	BlockSignals(True,SIGFPE);
#endif

#if defined(SIGUSR2)
	/* We are no longer interested in USR2 */
	BlockSignals(True,SIGUSR2);
#endif

	/* POSIX demands that signals are inherited. If the invoking process has
	 * these signals masked, we will have problems, as we won't recieve them. */
	BlockSignals(False, SIGHUP);
	BlockSignals(False, SIGUSR1);
	BlockSignals(False, SIGTERM);

	/* Ensure we leave no zombies until we
	 * correctly set up child handling below. */

	CatchChild();

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	umask(0);

	reopen_logs();

	DEBUG(0,("smbd version %s started.\n", samba_version_string()));
	DEBUGADD(0,("%s\n", COPYRIGHT_STARTUP_MESSAGE));

	DEBUG(2,("uid=%d gid=%d euid=%d egid=%d\n",
		 (int)getuid(),(int)getgid(),(int)geteuid(),(int)getegid()));

	/* Output the build options to the debug log */ 
	build_options(False);

	if (!lp_load_global(get_dyn_CONFIGFILE())) {
		ret = -1;
		goto done;
	}

	/* Init the security context and global current_user */
	init_sec_ctx();

	/*
	 * Initialize the event context. The event context needs to be
	 * initialized before the messaging context, cause the messaging
	 * context holds an event context.
	 */
	ev_ctx = global_event_context();
	if (ev_ctx == NULL) {
		ret = -1;
		goto done;
	}

	/*
	 * Init the messaging context
	 * FIXME: This should only call messaging_init()
	 */
	msg_ctx = global_messaging_context();
	if (msg_ctx == NULL) {
		ret = -1;
		goto done;
	}

	/*
	 * Reloading of the printers will not work here as we don't have a
	 * server info and rpc services set up. It will be called later.
	 */
	if (!reload_services(NULL, NULL, false)) {
		ret = -1;
		goto done;
	}

	/* ...NOTE... Log files are working from this point! */

	DEBUG(3,("loaded services\n"));

	init_structs();

	if (!profile_setup(msg_ctx, False)) {
		DEBUG(0,("ERROR: failed to setup profiling\n"));
		return -1;
	}

	int profiling_level = lp_smbd_profiling_level();
	main_server_id = messaging_server_id(msg_ctx);
	set_profile_level(profiling_level, &main_server_id);

#if HAVE_SETPGID
	//set process group for signal management.
	setpgid( (pid_t)0, (pid_t)0);
#endif

	if (!directory_exist(lp_lock_directory()))
		mkdir(lp_lock_directory(), 0755);

	if (!directory_exist(lp_pid_directory()))
		mkdir(lp_pid_directory(), 0755);

	pidfile_create(lp_pid_directory(), "smbd");

	NTSTATUS status = reinit_after_fork(msg_ctx, ev_ctx, false, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		exit_daemon("reinit_after_fork() failed", map_errno_from_nt_status(status));
	}

	struct smbd_parent_context *parent = talloc_zero(ev_ctx, struct smbd_parent_context);
	if (!parent) {
		// exit_server("talloc(struct smbd_parent_context) failed");
		return -1;
	}

	parent->interactive = true;
	parent->ev_ctx = ev_ctx;
	parent->msg_ctx = msg_ctx;
	am_parent = parent;

	struct tevent_signal *se = NULL;
	//se = tevent_add_signal(parent->ev_ctx, parent, SIGTERM, 0, smbd_parent_sig_term_handler, parent);
	se = tevent_add_signal(parent->ev_ctx, parent, SIGUSR2, 0, smbd_parent_sig_term_handler, parent);
	if (!se) {
		// exit_server("failed to setup SIGTERM handler");
		smbd_exit_server("failed to setup SIGTERM handler");
	}
	se = tevent_add_signal(parent->ev_ctx, parent, SIGHUP, 0, smbd_parent_sig_hup_handler, parent);
	if (!se) {
		// exit_server("failed to setup SIGHUP handler");
		smbd_exit_server("failed to setup SIGHUP handler");
	}

	/* Setup all the TDB's - including CLEAR_IF_FIRST tdb's. */

	if (smbd_memcache() == NULL) {
		// exit_daemon("no memcache available", EACCES);
		DBG_ERR("daemon failed to start: %s, error code %d\n", "no memcache available", EACCES);
		return 1;
	}

	memcache_set_global(smbd_memcache());

	/* Initialise the password backed before the global_sam_sid
	   to ensure that we fetch from ldap before we make a domain sid up */

	if(!initialize_password_db(false, ev_ctx)) {
		// exit(1);
		return 1;
	}

	if (!secrets_init()) {
		// exit_daemon("smbd can not open secrets.tdb", EACCES);
		DBG_ERR("daemon failed to start: %s, error code %d\n", "smbd can not open secrets.tdb", EACCES);
		return 1;
	}

	if(!get_global_sam_sid()) {
		// exit_daemon("Samba cannot create a SAM SID", EACCES);
		DBG_ERR("daemon failed to start: %s, error code %d\n", "Samba cannot create a SAM SID", EACCES);
		return 1;
	}

	struct server_id server_id = messaging_server_id(msg_ctx);
	status = smbXsrv_version_global_init(&server_id);
	if (!NT_STATUS_IS_OK(status)) {
		// exit_daemon("Samba cannot init server context", EACCES);
		DBG_ERR("daemon failed to start: %s, error code %d\n", "Samba cannot init server context", EACCES);
		return 1;
	}

	status = smbXsrv_client_global_init();
	if (!NT_STATUS_IS_OK(status)) {
		// exit_daemon("Samba cannot init clients context", EACCES);
		DBG_ERR("daemon failed to start: %s, error code %d\n", "Samba cannot init clients context", EACCES);
		return 1;
	}

	status = smbXsrv_session_global_init(msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		// exit_daemon("Samba cannot init session context", EACCES);
		DBG_ERR("daemon failed to start: %s, error code %d\n", "Samba cannot init session context", EACCES);
		return 1;
	}

	status = smbXsrv_tcon_global_init();
	if (!NT_STATUS_IS_OK(status)) {
		// exit_daemon("Samba cannot init tcon context", EACCES);
		DBG_ERR("daemon failed to start: %s, error code %d\n", "Samba cannot init tcon context", EACCES);
		return 1;
	}

	if (!locking_init()) {
		// exit_daemon("Samba cannot init locking", EACCES);
		DBG_ERR("daemon failed to start: %s, error code %d\n", "Samba cannot init locking", EACCES);
		return 1;
	}

	if (!leases_db_init(false)) {
		// exit_daemon("Samba cannot init leases", EACCES);
		DBG_ERR("daemon failed to start: %s, error code %d\n", "Samba cannot init leases", EACCES);
		return 1;
	}

	if (!smbd_notifyd_init(msg_ctx, true, &parent->notifyd)) {
		// exit_daemon("Samba cannot init notification", EACCES);
		DBG_ERR("daemon failed to start: %s, error code %d\n", "Samba cannot init notification", EACCES);
		return 1;
	}

	if (!cleanupd_init(msg_ctx, true, &parent->cleanupd)) {
		// exit_daemon("Samba cannot init the cleanupd", EACCES);
		return 1;
	}

	if (!messaging_parent_dgm_cleanup_init(msg_ctx)) {
		// exit(1);
		return 1;
	}

	if (!smbd_scavenger_init(NULL, msg_ctx, ev_ctx)) {
		// exit_daemon("Samba cannot init scavenging", EACCES);
		return 1;
	}

	if (!W_ERROR_IS_OK(registry_init_full())) {
		// exit_daemon("Samba cannot init registry", EACCES);
		return 1;
	}

	/* Open the share_info.tdb here, so we don't have to open
	   after the fork on every single connection.  This is a small
	   performance improvment and reduces the total number of system
	   fds used. */
	if (!share_info_db_init()) {
		// exit_daemon("ERROR: failed to load share info db.", EACCES);
		return 1;
	}

	status = init_system_session_info(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("ERROR: failed to setup system user info: %s.\n",
			  nt_errstr(status)));
		return -1;
	}

	if (!init_guest_session_info(NULL)) {
		DEBUG(0,("ERROR: failed to setup guest info.\n"));
		return -1;
	}

	if (!file_init_global()) {
		DEBUG(0, ("ERROR: file_init_global() failed\n"));
		return -1;
	}
	status = smbXsrv_open_global_init();
	if (!NT_STATUS_IS_OK(status)) {
		// exit_daemon("Samba cannot init global open", map_errno_from_nt_status(status));
		return 1;
	}

	/* This MUST be done before start_epmd() because otherwise
	 * start_epmd() forks and races against dcesrv_ep_setup() to
	 * call directory_create_or_exist() */
	if (!directory_create_or_exist(lp_ncalrpc_dir(), 0755)) {
		DEBUG(0, ("Failed to create pipe directory %s - %s\n",
			  lp_ncalrpc_dir(), strerror(errno)));
		return -1;
	}

	char *np_dir = talloc_asprintf(talloc_tos(), "%s/np", lp_ncalrpc_dir());
	if (!np_dir) {
		DEBUG(0, ("%s: Out of memory\n", __location__));
		return -1;
	}

	if (!directory_create_or_exist_strict(np_dir, geteuid(), 0700)) {
		DEBUG(0, ("Failed to create pipe directory %s - %s\n",
			  np_dir, strerror(errno)));
		return -1;
	}

	if (!dcesrv_ep_setup(ev_ctx, msg_ctx)) {
		// exit_daemon("Samba cannot setup ep pipe", EACCES);
		return 1;
	}	

done:

	return ret;
}

void release_resource(void)
{
#ifdef USE_DMAPI
	/* Destroy Samba DMAPI session only if we are master smbd process */
	if (am_parent) {
		if (!dmapi_destroy_session()) {
			DEBUG(0,("Unable to close Samba DMAPI session\n"));
		}
	}
#endif

	if (am_parent) {
		rpc_wkssvc_shutdown();
		rpc_dssetup_shutdown();
#ifdef DEVELOPER
		rpc_rpcecho_shutdown();
#endif
		rpc_netdfs_shutdown();
		rpc_initshutdown_shutdown();
		rpc_eventlog_shutdown();
		rpc_ntsvcs_shutdown();
		rpc_svcctl_shutdown();
		rpc_spoolss_shutdown();

		rpc_srvsvc_shutdown();
		rpc_winreg_shutdown();

		rpc_netlogon_shutdown();
		rpc_samr_shutdown();
		rpc_lsarpc_shutdown();
	}

	netlogon_creds_cli_close_global_db();
	// TALLOC_FREE(global_smbXsrv_client);
	smbprofile_dump();
	locking_end();
	printing_end();

	if (am_parent) {
		pidfile_unlink(lp_pid_directory(), PROCS_NAME);
	}
	// gencache_stabilize();

	global_messaging_context_free();
	global_event_context_free();
	TALLOC_FREE(smbd_memcache_ctx);
	am_parent = NULL;
}

void smb_server_exit_cleanly(const char *const explanation)
{
	DEBUG(3, ("Server exit, %s\n", explanation));

	struct smbXsrv_client *p = global_smbXsrv_client;
	for (; p != NULL;) {
		DLIST_REMOVE(global_smbXsrv_client, p);
		disconnect_smb_client(p);
		TALLOC_FREE(p);
		p = global_smbXsrv_client;
	}

	// disconnect_smb_client(global_smbXsrv_client);
	// TALLOC_FREE(global_smbXsrv_client);

	if(am_parent) {
		am_parent->exit_flag = true;
	}
}

void set_smb_callback(FN_ON_START start, FN_ON_EXIT exit, FN_ON_CONNECT connect, FN_ON_DISCONNECT disconnect)
{
	Callback.on_start = start;
	Callback.on_connect = connect;
	Callback.on_disconnect = disconnect;
	Callback.on_exit = exit;
}

void set_smb_share(const char *name, const char *path)
{
	lp_configure_set_share(name, path);
}

void set_smb_data_path(const char *path)
{
	lp_configure_set_data_path(path);
}

void set_smb_log_level(int level)
{
	lp_configure_set_log_level(level);
}

void add_smb_account(const char *usr, const char *pwd)
{
	struct smb_userinfo *account = accounts;
	for(; account != NULL; ) {
		if (strcmp_safe(account->usr, usr) == 0) {
			// already exist, delete
			DLIST_REMOVE(accounts, account);
			TALLOC_FREE(account);
			break;
		}
		account = account->next;
	}

	account = talloc(NULL, struct smb_userinfo);
	if (!account) {
		return;
	}

	account->usr = talloc_strdup(account, usr);
	account->pwd = talloc_strdup(account, pwd);

	DLIST_ADD(accounts, account);

	// already running
	if (am_parent && !am_parent->exit_flag) {
		set_smb_password(usr, pwd);
	}
}

void del_smb_account(const char *usr)
{
	struct smb_userinfo * account = accounts;
	for(; account != NULL; ) {
		if (strcmp_safe(account->usr, usr) == 0) {
			DLIST_REMOVE(accounts, account);
			TALLOC_FREE(account);
			break;
		}
		account = account->next;
	}

	// already running
	if (am_parent && !am_parent->exit_flag) {
		del_smb_password(usr);
	}
}