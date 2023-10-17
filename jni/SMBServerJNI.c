#include "errno.h"
#include "smbd/smbserver.h"
#include "com_leoon_jni_SMBServerJNI.h"

static struct CallbackContext{
    JNIEnv* env;
    jobject obj;

    //global variable
    //TODO: mutithreads callback.
    JavaVM *jvm;
    jobject g_obj;
}CallbckCtx;

void SMBServerJNI_onListen(const char* ip, unsigned port)
{
    JNIEnv *env = CallbckCtx.env;
    jobject obj = CallbckCtx.obj;

    jclass javaClass = (*env)->GetObjectClass(env, obj);
    if (javaClass != NULL) {
        jstring javaIP = (*env)->NewStringUTF(env, ip);
        jmethodID javaCallback = (*env)->GetMethodID(env, javaClass, "onListen", "(Ljava/lang/String;J)V");
        (*env)->CallVoidMethod(env, obj, javaCallback, javaIP, port);
        (*env)->DeleteLocalRef(env, javaIP);
    }
}

void SMBServerJNI_onStart(const char* username, const char* password)
{
    JNIEnv *env = CallbckCtx.env;
    jobject obj = CallbckCtx.obj;

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

void SMBServerJNI_onConnect(const char* client_name, const char* client_ip)
{
    JNIEnv *env = CallbckCtx.env;
    jobject obj = CallbckCtx.obj;

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

void SMBServerJNI_onLogon(const char* username)
{
    JNIEnv *env = CallbckCtx.env;
    jobject obj = CallbckCtx.obj;

    jclass javaClass = (*env)->GetObjectClass(env, obj);
    if (javaClass != NULL) {
        jstring javaUsername = (*env)->NewStringUTF(env, username);
        jmethodID javaCallback = (*env)->GetMethodID(env, javaClass, "onLogon", "(Ljava/lang/String;)V");
        (*env)->CallVoidMethod(env, obj, javaCallback, javaUsername);
        (*env)->DeleteLocalRef(env, javaUsername);
    }
}

void SMBServerJNI_onDisconnect(const char* client_ip)
{
    JNIEnv *env = CallbckCtx.env;
    jobject obj = CallbckCtx.obj;

    jclass javaClass = (*env)->GetObjectClass(env, obj);
    if (javaClass != NULL) {
        jstring javaClientIP = (*env)->NewStringUTF(env, client_ip);
        jmethodID javaCallback = (*env)->GetMethodID(env, javaClass, "onDisconnect", "(Ljava/lang/String;)V");
        (*env)->CallVoidMethod(env, obj, javaCallback, javaClientIP);
        (*env)->DeleteLocalRef(env, javaClientIP);
    }
}

void SMBServerJNI_onExit(void)
{
    JNIEnv *env = CallbckCtx.env;
    jobject obj = CallbckCtx.obj;

    jclass javaClass = (*env)->GetObjectClass(env, obj);
    if (javaClass != NULL) {
        jmethodID javaCallback = (*env)->GetMethodID(env, javaClass, "onExit", "()V");
        (*env)->CallVoidMethod(env, obj, javaCallback);
    }

    //server exit, release callback context.
    if(CallbckCtx.g_obj) {
        (*env)->DeleteGlobalRef(env, CallbckCtx.g_obj);
        CallbckCtx.g_obj = NULL;
    }
    CallbckCtx.jvm = NULL;
    CallbckCtx.obj = NULL;
    CallbckCtx.env = NULL;
}

JNIEXPORT jint JNICALL Java_com_leoon_jni_SMBServerJNI_start_1smb_1server(JNIEnv *env, jobject thiz)
{
    if(CallbckCtx.env && CallbckCtx.env != env) {
        return -1;
    }

    CallbckCtx.env = env;
    CallbckCtx.obj = thiz;
    if((*env)->GetJavaVM(env, &CallbckCtx.jvm) != JNI_OK) {
        return -2;
    }
    CallbckCtx.g_obj = (*env)->NewGlobalRef(env, thiz);
    if (!CallbckCtx.g_obj){
        return -2;
    }

    set_smb_callback(SMBServerJNI_onListen, SMBServerJNI_onStart, SMBServerJNI_onConnect, 
                     SMBServerJNI_onLogon, SMBServerJNI_onDisconnect, SMBServerJNI_onExit);

    return start_smb_server();
}

JNIEXPORT jint JNICALL Java_com_leoon_jni_SMBServerJNI_stop_1smb_1server(JNIEnv *env, jobject thiz)
{
    return stop_smb_server();
}

JNIEXPORT jint JNICALL Java_com_leoon_jni_SMBServerJNI_set_1smb_1share(JNIEnv *env, jobject thiz, jstring share_name, jstring share_path)
{
    const char *name = (*env)->GetStringUTFChars(env, share_name, NULL);
    const char *path = (*env)->GetStringUTFChars(env, share_path, NULL);
    if (NULL == name || NULL == path) {
        errno = EINVAL;
        return -1;
    }
    set_smb_share(name , path);
    return 0;
}

JNIEXPORT jint JNICALL Java_com_leoon_jni_SMBServerJNI_set_1smb_1data_1path(JNIEnv *env, jobject thiz, jstring data_path)
{
    const char *path = (*env)->GetStringUTFChars(env, data_path, NULL);
    if (NULL == path) {
        errno = EINVAL;
        return -1;
    }

    set_smb_data_path(path);
    return 0;
}

JNIEXPORT jint JNICALL Java_com_leoon_jni_SMBServerJNI_set_1smb_1log_1level(JNIEnv *env, jobject thiz, jint log_level)
{
    set_smb_log_level(log_level);
    return 0;
}

JNIEXPORT jint JNICALL Java_com_leoon_jni_SMBServerJNI_set_1smb_1account(JNIEnv *env , jobject thiz, jstring usr, jstring pwd)
{
    const char *username = (*env)->GetStringUTFChars(env, usr, NULL);
    const char *password = (*env)->GetStringUTFChars(env, pwd, NULL);
    if (NULL == username || NULL == password) {
        errno = EINVAL;
        return -1;
    }

    set_smb_account(username, password);
    return 0;
}