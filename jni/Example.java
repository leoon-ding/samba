package com.leoon.jni;

import com.leoon.jni.SMBServerJNI;

public class Example {

    private void Test(){
        System.out.println("[Java] Example Test().");
    }

    // Test
    public static void main(String[] args) {
        Example exp = new Example();

        SMBServerJNI smbsrv = new SMBServerJNI("/home/leon/mobiledrive/smb.conf", new SMBServerJNI.CallBack(){
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
        smbsrv.start();
    }
}