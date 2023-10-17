package com.leoon.jni;

import com.leoon.jni.SMBServerJNI;

public class Example {

    // Test
    public static void main(String[] args) {
        SMBServerJNI smbsrv = new SMBServerJNI(new SMBServerJNI.CallBack(){
            @Override
            public void onListen(String ip, long port) {
                System.out.println("Server on listen: ip=" + ip + ", port=" + String.valueOf(port));
            }

            @Override
            public void onStart(String account, String password) {
                System.out.println("Server on start: account=" + account + ", password=" + password);
            }

            @Override
            public void onConnect(String name, String ip) {
                System.out.println("Server on connect: name=" + name + ", ip=" + ip);
            }

            @Override
            public void onLogon(String account) {
                System.out.println("Server on logon: account=" + account);
            }

            @Override
            public void onDisconnect(String ip) {
                System.out.println("Server on disconnect: ip=" + ip);
            }

            @Override
            public void onExit() {
                System.out.println("Server on exit.");
            }
        });

        smbsrv.setAccount("admin", "123456");
        smbsrv.setDataPath("/Users/Leo/Projects/smbconf");
        smbsrv.setSharePath("share", "/Users/Leo/Documents");
        smbsrv.start();
    }
}