#include "stdio.h"
#include "../source3/smbd/smbserver.h"

void onStart(const char* ip, int port)
{
    printf("server start, ip = %s, port = %d\n", ip, port);
}

void onConnect(const char* username, const char* client_ip)
{
    printf("client connected, username = %s, ip = %s\n", username, client_ip);
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
    set_smb_callback(onStart, onExit, onConnect, onDisconnect);
    set_smb_data_path("/Users/Leo/Projects/smbconf");
    add_smb_account("admin", "admin");
    set_smb_share("share", "/Users/Leo/Downloads");
    set_smb_log_level(5);
    int ret = start_smb_server();
    if (ret != 0)
    {
        printf("server exit, ret = %d\n", ret);
    }
    
    return 0;
}
