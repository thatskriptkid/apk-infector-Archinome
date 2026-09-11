package com.example.legacyapp;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class LegacyReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context ctx, Intent i) {
        Log.i("LEGACYAPP", "LEGACY_RECEIVER_ONRECEIVE action=" + (i == null ? "?" : i.getAction()));
    }
}
