package com.example.legacyapp;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.i("LEGACYAPP", "LEGACY_MAIN_ONCREATE");
    }
}
