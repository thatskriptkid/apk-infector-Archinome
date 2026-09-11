package com.example.legacyapp;

import android.app.Application;
import android.util.Log;

public class MyApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        Log.i("LEGACYAPP", "LEGACY_APP_ONCREATE");
    }
}
