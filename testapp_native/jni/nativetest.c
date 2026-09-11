/* Baseline "original" native library of the test app.
 * Exports a real JNI method so we can prove that (a) the dependency chain keeps
 * the original implementation reachable, and (b) symbol interposition from an
 * injected library really shadows it. */
#include <jni.h>
#include <android/log.h>
#include <unistd.h>

#define TAG "ARCHINOME_TEST"

__attribute__((constructor)) static void nativetest_ctor(void) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "ORIGINAL_LIB_CTOR pid=%d", getpid());
}

JNIEXPORT jstring JNICALL
Java_com_example_nativetest_MainActivity_stringFromJNI(JNIEnv *env, jobject thiz) {
    (void) thiz;
    __android_log_print(ANDROID_LOG_INFO, TAG, "ORIGINAL_stringFromJNI called");
    return (*env)->NewStringUTF(env, "ORIGINAL libnativetest.so");
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) vm; (void) reserved;
    __android_log_print(ANDROID_LOG_INFO, TAG, "ORIGINAL_JNI_ONLOAD");
    return JNI_VERSION_1_6;
}
