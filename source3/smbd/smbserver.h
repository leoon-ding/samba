#ifndef _SMB_SERVER_H
#define _SMB_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#define __SMB_ERRNO_BASE__  10000

typedef void (*FN_ON_START)(const char* ip, int port);

typedef void (*FN_ON_CONNECT)(const char* account, const char* client_ip);

typedef void (*FN_ON_DISCONNECT)(const char* client_ip);

typedef void (*FN_ON_EXIT)(void);

int start_smb_server(void);

int stop_smb_server(void);

void set_smb_share(const char *name, const char *path);

void set_smb_data_path(const char *path);

void set_smb_log_level(int level);

void set_smb_callback(FN_ON_START start, FN_ON_EXIT exit, FN_ON_CONNECT connect, FN_ON_DISCONNECT disconnect);

void add_smb_account(const char *usr, const char *pwd);

void del_smb_account(const char *usr);

#ifdef __cplusplus
}
#endif

#endif /* _SMB_SERVER_H */
