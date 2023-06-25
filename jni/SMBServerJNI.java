package com.leoon.jni;

public class SMBServerJNI {
    static {
        // Load native library at runtime
        // System.loadLibrary("smbserver");
        System.load("/home/leon/projects/samba/bin/default/source3/libsmbserver.so");
    }

    public interface CallBack{
        void onListen(String ip, long port);

        void onStart(String account, String password);

        void onConnect(String name, String ip);

        void onLogon(String account);

        void onDisconnect(String ip);

        void onExit();
    }

    final private String configureFile;

    final private CallBack callback; 

    private native int startSMBServer(String cfgFile);

    private native int stopSMBServer();

    private native int addSMBShare(String cfgFile, String fileName, String sharedName);

    public SMBServerJNI(String cfgFile, CallBack callback) {
        this.configureFile = cfgFile;
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
        return startSMBServer(configureFile);
    }

    public int stop() {
        return stopSMBServer();
    }

    public int addShare(String fileName, String sharedName) {
        return addSMBShare(configureFile, fileName, sharedName);
    }
}
