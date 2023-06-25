#include "errno.h"
#include "smbd/smbserver.h"
#include "com_leoon_jni_SMBServerJNI.h"

struct SMBServerJNICallBackContext{
    JNIEnv* env;
    jobject obj;
};

void SMBServerJNI_onListen(CALLBACK_CTX *cb_ctx, const char* ip, unsigned port)
{
    struct SMBServerJNICallBackContext *ctx = (struct SMBServerJNICallBackContext *)cb_ctx;
    JNIEnv *env = ctx->env;
    jobject obj = ctx->obj;

    jclass javaClass = (*env)->GetObjectClass(env, obj);
    if (javaClass != NULL) {
        jstring javaIP = (*env)->NewStringUTF(env, ip);
        jmethodID javaCallback = (*env)->GetMethodID(env, javaClass, "onListen", "(Ljava/lang/String;J)V");
        (*env)->CallVoidMethod(env, obj, javaCallback, javaIP, port);
        (*env)->DeleteLocalRef(env, javaIP);
    }
}

void SMBServerJNI_onStart(CALLBACK_CTX *cb_ctx, const char* username, const char* password)
{
    struct SMBServerJNICallBackContext *ctx = (struct SMBServerJNICallBackContext *)cb_ctx;
    JNIEnv *env = ctx->env;
    jobject obj = ctx->obj;

    jclass javaClass = (*env)->GetObjectClass(env, obj);
    if (javaClass != NULL) {
        jstring javaUsername = (*env)->NewStringUTF(env, username);
        jstring javaPassword = (*env)->NewStringUTF(env, password);
        jmethodID javaCallback = (*env)->GetMethodID(env, javaClass, "onStart", "(Ljava/lang/String;Ljava/lang/String;)V");
        (*env)->CallVoidMethod(env, obj, javaCallback, javaUsername, javaPassword);
        (*env)->DeleteLocalRef(env, javaPassword);
        (*env)->DeleteLocalRef(env, javaUsername);
    }
}

void SMBServerJNI_onConnect(CALLBACK_CTX *cb_ctx, const char* client_name, const char* client_ip)
{
    struct SMBServerJNICallBackContext *ctx = (struct SMBServerJNICallBackContext *)cb_ctx;
    JNIEnv *env = ctx->env;
    jobject obj = ctx->obj;

    jclass javaClass = (*env)->GetObjectClass(env, obj);
    if (javaClass != NULL) {
        jstring javaClientName = (*env)->NewStringUTF(env, client_name);
        jstring javaClientIP = (*env)->NewStringUTF(env, client_ip);
        jmethodID javaCallback = (*env)->GetMethodID(env, javaClass, "onConnect", "(Ljava/lang/String;Ljava/lang/String;)V");
        (*env)->CallVoidMethod(env, obj, javaCallback, javaClientName, javaClientIP);
        (*env)->DeleteLocalRef(env, javaClientIP);
        (*env)->DeleteLocalRef(env, javaClientName);
    }
}

void SMBServerJNI_onLogon(CALLBACK_CTX *cb_ctx, const char* username)
{
    struct SMBServerJNICallBackContext *ctx = (struct SMBServerJNICallBackContext *)cb_ctx;
    JNIEnv *env = ctx->env;
    jobject obj = ctx->obj;

    jclass javaClass = (*env)->GetObjectClass(env, obj);
    if (javaClass != NULL) {
        jstring javaUsername = (*env)->NewStringUTF(env, username);
        jmethodID javaCallback = (*env)->GetMethodID(env, javaClass, "onLogon", "(Ljava/lang/String;)V");
        (*env)->CallVoidMethod(env, obj, javaCallback, javaUsername);
        (*env)->DeleteLocalRef(env, javaUsername);
    }
}

void SMBServerJNI_onDisconnect(CALLBACK_CTX *cb_ctx, const char* client_ip)
{
    struct SMBServerJNICallBackContext *ctx = (struct SMBServerJNICallBackContext *)cb_ctx;
    JNIEnv *env = ctx->env;
    jobject obj = ctx->obj;

    jclass javaClass = (*env)->GetObjectClass(env, obj);
    if (javaClass != NULL) {
        jstring javaClientIP = (*env)->NewStringUTF(env, client_ip);
        jmethodID javaCallback = (*env)->GetMethodID(env, javaClass, "onDisconnect", "(Ljava/lang/String;)V");
        (*env)->CallVoidMethod(env, obj, javaCallback, javaClientIP);
        (*env)->DeleteLocalRef(env, javaClientIP);
    }
}

void SMBServerJNI_onExit(CALLBACK_CTX *cb_ctx)
{
    struct SMBServerJNICallBackContext *ctx = (struct SMBServerJNICallBackContext *)cb_ctx;
    JNIEnv *env = ctx->env;
    jobject obj = ctx->obj;

    jclass javaClass = (*env)->GetObjectClass(env, obj);
    if (javaClass != NULL) {
        jmethodID javaCallback = (*env)->GetMethodID(env, javaClass, "onExit", "()V");
        (*env)->CallVoidMethod(env, obj, javaCallback);
    }
}

JNIEXPORT jint JNICALL Java_com_leoon_jni_SMBServerJNI_startSMBServer(JNIEnv *env, jobject thiz, jstring cfg_file)
{
    const char *filename = (*env)->GetStringUTFChars(env, cfg_file, NULL);
    if (NULL == filename) {
        errno = EINVAL;
        return -1;
    }

    struct SMBServerJNICallBackContext cb_ctx;
    cb_ctx.env = env;
    cb_ctx.obj = thiz;

    return start_smb_server(filename, (CALLBACK_CTX*)&cb_ctx, SMBServerJNI_onListen,
                                                              SMBServerJNI_onStart,
                                                              SMBServerJNI_onConnect,
                                                              SMBServerJNI_onLogon,
                                                              SMBServerJNI_onDisconnect,
                                                              SMBServerJNI_onExit);
}

JNIEXPORT jint JNICALL Java_com_leoon_jni_SMBServerJNI_stopSMBServer(JNIEnv *env, jobject thiz)
{
    return stop_smb_server();
}

JNIEXPORT jint JNICALL Java_com_leoon_jni_SMBServerJNI_addSMBShare(JNIEnv *env, jobject thiz, jstring cfg_file, 
                                                                   jstring file_name, jstring shared_name)
{
    const char *cfgname = (*env)->GetStringUTFChars(env, cfg_file, NULL);
    const char *filename = (*env)->GetStringUTFChars(env, file_name, NULL);
    const char *sharedname = (*env)->GetStringUTFChars(env, shared_name, NULL);
    if (NULL == cfgname || NULL == filename || NULL == sharedname) {
        errno = EINVAL;
        return -1;
    }

    return add_smb_share(cfgname, filename, sharedname);
}