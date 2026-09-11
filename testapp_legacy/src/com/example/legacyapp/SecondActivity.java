package com.example.legacyapp;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class SecondActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.i("LEGACYAPP", "LEGACY_SECOND_ONCREATE");
    }
}
