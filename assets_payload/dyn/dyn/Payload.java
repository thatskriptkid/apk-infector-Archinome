package dyn;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.security.MessageDigest;

/**
 * The hidden payload. It only ever exists inside the encrypted asset, so it is
 * not listed among the APK classes*.dex entries and cannot be read with a plain
 * `unzip` + `strings` pass over the APK.
 *
 * The loader invokes executePayload(Context, dataDir, pkg) reflectively; ctx is
 * null on the AppComponentFactory path, where no Context exists yet.
 */
public class Payload {

    private static final String TAG = "ARCHINOME";

    public void executePayload(Context ctx, String dataDir, String pkg) {
        Log.i(TAG, "ASSET_PAYLOAD_EXECUTED pkg=" + pkg
                + " dataDir=" + dataDir
                + " ctx=" + (ctx != null)
                + " pid=" + android.os.Process.myPid());
        try {
            File dir = new File(dataDir, "archinome");
            if (!dir.exists()) {
                dir.mkdirs();
            }
            File proof = new File(dir, "archinome_asset_proof.txt");
            FileOutputStream out = new FileOutputStream(proof, true);
            try {
                out.write(("ASSET_PAYLOAD_EXECUTED ts=" + System.currentTimeMillis()
                        + " pkg=" + pkg
                        + " pid=" + android.os.Process.myPid()
                        + " loader=" + getClass().getClassLoader().getClass().getName()
                        + "\n").getBytes("UTF-8"));
            } finally {
                out.close();
            }
            Log.i(TAG, "ASSET_PROOF_WRITTEN " + proof.getAbsolutePath());
            logDexDigest(dataDir);
        } catch (Throwable t) {
            Log.e(TAG, "ASSET_PROOF_FAIL " + t);
        }
    }

    /**
     * SHA-256 of the dex the loader dropped, so the on-device result can be
     * compared byte for byte with `assetcrypt info` on the same asset. Costs
     * nothing and needs no root: the digest shows up in logcat.
     */
    private void logDexDigest(String dataDir) {
        try {
            File dex = new File(new File(dataDir, "archinome"), "archinome.dex");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192];
            java.io.FileInputStream in = new java.io.FileInputStream(dex);
            try {
                int n;
                while ((n = in.read(buf)) > 0) {
                    md.update(buf, 0, n);
                }
            } finally {
                in.close();
            }
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) {
                sb.append(String.format("%02x", b));
            }
            Log.i(TAG, "ASSET_DEX_SHA256 " + sb + " len=" + dex.length());
        } catch (Throwable t) {
            Log.e(TAG, "ASSET_DEX_SHA256_FAIL " + t);
        }
    }
}
