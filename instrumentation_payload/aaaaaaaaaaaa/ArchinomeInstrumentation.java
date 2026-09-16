package aaaaaaaaaaaa;

import android.app.Instrumentation;
import android.os.Bundle;
import android.util.Log;

/**
 * Instrumentation payload injected as the manifest android:name of
 * <instrumentation>. The constructor runs as soon as the framework
 * instantiates the class.
 */
public class ArchinomeInstrumentation extends Instrumentation {

    public ArchinomeInstrumentation() {
        Log.i("ARCHINOME", "INSTRUMENTATION_PAYLOAD_EXECUTED");
    }

    @Override
    public void onCreate(Bundle b) {
        super.onCreate(b);
    }
}
