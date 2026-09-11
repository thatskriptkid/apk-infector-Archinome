package aaaaaaaaaaaa;

import android.util.Log;

public class payload {

    public static final String TAG = "ARCHINOME";

    public static void log(String msg) {
        Log.i(TAG, msg);
    }

    public void executePayload() {
        log("APPFACTORY_PAYLOAD_EXECUTED pid=" + android.os.Process.myPid());
    }
}
