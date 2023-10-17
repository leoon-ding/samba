package com.leoon.jni;

public class SMBServerJNI {
    static {
        // Load native library at runtime
        // System.loadLibrary("smbserver");
        System.load("/Users/Leo/Projects/samba/bin/default/source3/libsmbserver.dylib");
    }

    public interface CallBack{
        void onListen(String ip, long port);

        void onStart(String account, String password);

        void onConnect(String name, String ip);

        void onLogon(String account);

        void onDisconnect(String ip);

        void onExit();
    }

    final private CallBack callback; 

    private native int start_smb_server();

    private native int stop_smb_server();

    private native int set_smb_share(String share_name, String share_path);

    private native int set_smb_data_path(String data_path);

    private native int set_smb_log_level(int level);

    private native int set_smb_account(String usr, String pwd);

    public SMBServerJNI(CallBack callback) {
        this.callback = callback;
    }

    private void onListen(String ip, long port) {
        //自行执行回调后的操作
        if(callback != null) {
            callback.onListen(ip, port);
        }
    }

    private void onStart(String account, String password) {
        //自行执行回调后的操作
        if(callback != null) {
            callback.onStart(account, password);
        }
    }

    private void onConnect(String name, String ip) {
        //自行执行回调后的操作
        if(callback != null) {
            callback.onConnect(name, ip);
        }
    }

    private void onLogon(String account) {
        //自行执行回调后的操作
        if(callback != null) {
            callback.onLogon(account);
        }
    }

    private void onDisconnect(String ip) {
        //自行执行回调后的操作
        if(callback != null) {
            callback.onDisconnect(ip);
        }
    }

    private void onExit() {
        //自行执行回调后的操作
        if(callback != null) {
            callback.onExit();
        }
    }

    public int start() {
        return start_smb_server();
    }

    public int stop() {
        return stop_smb_server();
    }

    public void setDataPath(String path) {
        set_smb_data_path(path);
    }

    public void setSharePath(String name, String path) {
        set_smb_share(name, path);
    }

    public void setAccount(String usr, String pwd) {
        set_smb_account(usr, pwd);
    }

    public void setLogLevel(int level) {
        set_smb_log_level(level);
    }
}
