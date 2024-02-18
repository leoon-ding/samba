package com.leoon.jni;

import com.leoon.jni.SMBServerJNI;

public class Example {

    // Test
    public static void main(String[] args) {
        SMBServerJNI smbsrv = new SMBServerJNI(new SMBServerJNI.CallBack(){
            @Override
            public void onStart(String ip, int port) {
                System.out.println("Server on Start: ip=" + ip + ", port=" + String.valueOf(port));
            }

            @Override
            public void onConnect(String user, String ip) {
                System.out.println("Server on connect: user=" + user + ", ip=" + ip);
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

        smbsrv.addAccount("admin", "admin");
        smbsrv.setDataPath("/Users/Leo/Projects/smbconf");
        smbsrv.setSharePath("share", "/Users/Leo/Downloads");
        smbsrv.start();

        System.out.println("JIN test finished!!");
    }
}