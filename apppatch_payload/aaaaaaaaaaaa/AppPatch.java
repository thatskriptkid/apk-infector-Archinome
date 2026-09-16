package aaaaaaaaaaaa;

import android.util.Log;

/**
 * Application-level payload hook. Invoked from a foreign dex via
 * invoke-static {}, Laaaaaaaaaaaa/AppPatch;->run()V.
 */
public class AppPatch {
    public static void run() {
        Log.i("ARCHINOME", "APP_PATCH_EXECUTED");
    }
}
