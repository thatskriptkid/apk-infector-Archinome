package dyn;

import android.util.Log;

/**
 * Out-of-band payload: NOT part of the APK, delivered as a standalone dex and
 * resolved through the ClassLoader that ArchinomeAppComponentFactory installs
 * in instantiateClassLoader().
 */
public class Payload {

    public static void run() {
        Log.i("ARCHINOME", "DYN_PAYLOAD_EXECUTED_FROM_EXTERNAL_DEX pid="
                + android.os.Process.myPid());
    }
}
