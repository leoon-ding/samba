#include "stdio.h"
#include "../source3/smbd/smbserver.h"

void onListen(const char* ip, unsigned port)
{
    printf("server listing, ip = %s, port = %d\n", ip, port);
}

void onStart(const char* username, const char* password)
{
    printf("server started, usr = %s, pwd = %s\n", username, password);
}

void onConnect(const char* client_name, const char* client_ip)
{
    printf("client connected, client = %s, ip = %s\n", client_name, client_ip);
}

void onLogon(const char* username)
{
    printf("user logon sucessfull, account = %s\n", username);
}

void onDisconnect(const char* client_ip)
{
    printf("client disconnected, ip = %s\n", client_ip);
}

void onExit(void)
{
    printf("server exited.\n");
}

int main(int argc,const char *argv[])
{
    set_smb_callback(onListen, onStart, onConnect, onLogon, onDisconnect, onExit);
    set_smb_data_path("/Users/Leo/Projects/smbconf");
    set_smb_account("admin", "admin");
    set_smb_share("share", "/Users/Leo/Downloads");
    set_smb_log_level(5);
    int ret = start_smb_server();
    if (ret != 0)
    {
        printf("server exit, ret = %d\n", ret);
    }
    
    return 0;
}
