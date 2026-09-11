package aaaaaaaaaaaa;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Trigger: BroadcastReceiver injection (option 5 shape) -- onReceive has a Context. */
public class ArchinomeReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        AssetLoader.log("ASSETRECEIVER_ONRECEIVE " + (intent != null ? intent.getAction() : "null"));
        AssetLoader.run(context);
    }
}
