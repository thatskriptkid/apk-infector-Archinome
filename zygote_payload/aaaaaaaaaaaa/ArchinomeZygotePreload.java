package aaaaaaaaaaaa;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.util.Log;

/**
 * Zygote preload payload injected as the manifest
 * android:zygotePreloadName. doPreload runs inside the zygote process
 * before the app forks.
 */
public class ArchinomeZygotePreload implements ZygotePreload {

    @Override
    public void doPreload(ApplicationInfo info) {
        Log.i("ARCHINOME", "ZYGOTE_PRELOAD_EXECUTED");
    }
}
