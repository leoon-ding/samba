package com.leoon.jni;

public class SMBServerJNI {
    static {
        // Load native library at runtime
        // System.loadLibrary("smbserver");
        System.load("/Users/Leo/Projects/VisualStudioProjects/samba/bin/default/source3/libsmbserver.dylib");
    }

    public interface CallBack{
        void onStart(String ip, int port);

        void onConnect(String username, String ip);

        void onDisconnect(String ip);

        void onExit();
    }

    final private CallBack callback; 

    private native int start_smb_server();

    private native int stop_smb_server();

    private native int set_smb_share(String share_name, String share_path);

    private native int set_smb_data_path(String data_path);

    private native int set_smb_log_level(int level);

    private native int add_smb_account(String usr, String pwd);

    private native int del_smb_account(String usr);

    public SMBServerJNI(CallBack callback) {
        this.callback = callback;
    }

    public void onStart(String ip, int port) {
        //自行执行回调后的操作
        if(callback != null) {
            callback.onStart(ip, port);
        }
    }

    public void onConnect(String username, String ip) {
        //自行执行回调后的操作
        if(callback != null) {
            callback.onConnect(username, ip);
        }
    }

    public void onDisconnect(String ip) {
        //自行执行回调后的操作
        if(callback != null) {
            callback.onDisconnect(ip);
        }
    }

    public void onExit() {
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

    public void addAccount(String usr, String pwd) {
        add_smb_account(usr, pwd);
    }

    public void delAccount(String usr) {
        del_smb_account(usr);
    }

    public void setLogLevel(int level) {
        set_smb_log_level(level);
    }
}
