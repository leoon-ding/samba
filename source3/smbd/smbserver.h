#ifndef _SMB_SERVER_H
#define _SMB_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#define __SMB_ERRNO_BASE__  10000

typedef void (*FN_ON_LISTEN)(const char* ip, unsigned port);

typedef void (*FN_ON_START)(const char* username, const char* password);

typedef void (*FN_ON_CONNECT)(const char* client_name, const char* client_ip);

typedef void (*FN_ON_LOGON)(const char* username);

typedef void (*FN_ON_DISCONNECT)(const char* client_ip);

typedef void (*FN_ON_EXIT)(void);

int start_smb_server(void);

int stop_smb_server(void);

void set_smb_share(const char *name, const char *path);

void set_smb_data_path(const char *path);

void set_smb_log_level(int level);

void set_smb_callback(FN_ON_LISTEN listen, FN_ON_START start, FN_ON_CONNECT connect,
                      FN_ON_LOGON logon, FN_ON_DISCONNECT disconnect,FN_ON_EXIT exit);

void set_smb_account(const char *usr, const char *pwd);

#ifdef __cplusplus
}
#endif

#endif /* _SMB_SERVER_H */
