#ifndef _SMB_SERVER_H
#define _SMB_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#define __SMB_ERRNO_BASE__  10000

typedef struct callback_context{} CALLBACK_CTX;

typedef void (*FN_ON_LISTEN)(CALLBACK_CTX* ctx, const char* ip, unsigned port);

typedef void (*FN_ON_START)(CALLBACK_CTX* ctx, const char* username, const char* password);

typedef void (*FN_ON_CONNECT)(CALLBACK_CTX* ctx, const char* client_name, const char* client_ip);

typedef void (*FN_ON_LOGON)(CALLBACK_CTX* ctx, const char* username);

typedef void (*FN_ON_DISCONNECT)(CALLBACK_CTX* ctx, const char* client_ip);

typedef void (*FN_ON_EXIT)(CALLBACK_CTX* ctx);

int add_smb_share(const char* cfgfile, const char *filename, const char *sharedname);

int del_smb_share(const char* cfgfile, const char *filename);

int start_smb_server(const char *cfg_file, CALLBACK_CTX* cb_ctx, FN_ON_LISTEN on_listen,
                                           FN_ON_START on_start, FN_ON_CONNECT on_connect,
                                           FN_ON_LOGON on_logon, FN_ON_DISCONNECT on_disconnect,
                                           FN_ON_EXIT on_exit);

int stop_smb_server(void);

#ifdef __cplusplus
}
#endif

#endif /* _SMB_SERVER_H */
