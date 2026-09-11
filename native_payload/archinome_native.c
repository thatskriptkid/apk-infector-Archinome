/* Archinome native payload.
 *
 * Loaded either as a DT_NEEDED dependency of a patched host library, or as a
 * drop-in replacement ("stub") for a renamed original library. Runs code in the
 * target process before the host library's own constructors, with no root.
 *
 * Build-time knobs (see build.sh / build_stub.sh):
 *   -DARCHINOME_TAG="..."        label carried in the log lines
 *   -DARCHINOME_FORWARD_JNI="..."  stub mode: forward JNI_OnLoad to this library
 *   -DARCHINOME_HOOK_TESTAPP       also interpose a real JNI method (test only)
 */
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef ARCHINOME_TAG
#define ARCHINOME_TAG "archinome"
#endif

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "ARCHINOME_NATIVE", __VA_ARGS__)

/* Proof of execution inside the target process: the app can always write to its
 * own data directory, so no root and no SELinux relaxation are involved. */
static void archinome_proof(const char *what) {
    char pkg[256] = {0};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, pkg, sizeof(pkg) - 1);
        close(fd);
        if (n > 0) pkg[n] = '\0';
    }
    const char *bases[] = {"/data/user/0/%s", "/data/data/%s", NULL};
    const char *subs[] = {"files", "cache", NULL};
    for (int b = 0; bases[b] != NULL; ++b) {
        for (int s = 0; subs[s] != NULL; ++s) {
            char dir[512];
            snprintf(dir, sizeof(dir), bases[b], pkg);
            size_t n = strlen(dir);
            snprintf(dir + n, sizeof(dir) - n, "/%s", subs[s]);
            /* files/ is created lazily by the framework, so make it if missing. */
            if (mkdir(dir, 0700) != 0 && errno != EEXIST) continue;
            char path[640];
            snprintf(path, sizeof(path), "%s/archinome_native.txt", dir);
            int f = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (f < 0) continue;
            char line[512];
            int ln = snprintf(line, sizeof(line), "%s tag=%s pid=%d uid=%d\n",
                              what, ARCHINOME_TAG, getpid(), getuid());
            if (ln > 0) {
                ssize_t w = write(f, line, (size_t) ln);
                (void) w;
            }
            close(f);
            LOG("NATIVE_PROOF_WRITTEN %s", path);
            return;
        }
    }
    LOG("NATIVE_PROOF_FAILED errno=%d pkg=%s", errno, pkg);
}

__attribute__((constructor)) static void archinome_ctor(void) {
    LOG("NATIVE_PAYLOAD_CTOR tag=%s pid=%d uid=%d", ARCHINOME_TAG, getpid(), getuid());
    archinome_proof("CTOR");
#ifdef ARCHINOME_FORWARD_JNI
    LOG("NATIVE_STUB_FORWARD_TARGET %s", ARCHINOME_FORWARD_JNI);
#endif
    LOG("NATIVE_PAYLOAD_CTOR_DONE");
}

#ifdef ARCHINOME_FORWARD_JNI
typedef jint (*archinome_jnionload_fn)(JavaVM *, void *);
#endif

/* The platform calls JNI_OnLoad on the library it opened by name. In stub mode
 * that is us, so the original implementation must be forwarded to - otherwise we
 * would silently drop the host library's runtime initialisation. */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOG("NATIVE_JNI_ONLOAD pid=%d", getpid());
    archinome_proof("JNI_ONLOAD");
#ifdef ARCHINOME_FORWARD_JNI
    void *h = dlopen(ARCHINOME_FORWARD_JNI, RTLD_NOW | RTLD_NOLOAD);
    if (h == NULL) h = dlopen(ARCHINOME_FORWARD_JNI, RTLD_NOW);
    if (h != NULL) {
        archinome_jnionload_fn fwd =
            (archinome_jnionload_fn) dlsym(h, "JNI_OnLoad");
        if (fwd != NULL) {
            LOG("NATIVE_STUB_FORWARDING_JNI_ONLOAD -> %s", ARCHINOME_FORWARD_JNI);
            return fwd(vm, reserved);
        }
        LOG("NATIVE_STUB_NO_JNI_ONLOAD_IN %s", ARCHINOME_FORWARD_JNI);
    } else {
        LOG("NATIVE_STUB_FORWARD_DLOPEN_FAILED %s: %s",
            ARCHINOME_FORWARD_JNI, dlerror());
    }
#endif
    return JNI_VERSION_1_6;
}

#ifdef ARCHINOME_HOOK_TESTAPP
/* Interposition demo: the host library exports this symbol too, but the dynamic
 * linker resolves it in the library it opened first, i.e. in us. */
JNIEXPORT jstring JNICALL
Java_com_example_nativetest_MainActivity_stringFromJNI(JNIEnv *env, jobject thiz) {
    (void) thiz;
    LOG("NATIVE_HOOK_INTERCEPTED Java_com_example_nativetest_MainActivity_stringFromJNI");
    archinome_proof("HOOK");
    return (*env)->NewStringUTF(env, "INTERCEPTED by Archinome (native symbol hook)");
}
#endif
