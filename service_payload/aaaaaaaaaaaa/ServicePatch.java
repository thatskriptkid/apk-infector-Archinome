package aaaaaaaaaaaa;

import android.util.Log;

/**
 * Service-lifetime payload. Injected code calls
 * invoke-static {}, Laaaaaaaaaaaa/ServicePatch;->run()V from a foreign dex,
 * so run() must stay public, static and argument-less.
 */
public class ServicePatch {
    public static void run() {
        Log.i("ARCHINOME", "SERVICE_PATCH_EXECUTED");
    }
}
