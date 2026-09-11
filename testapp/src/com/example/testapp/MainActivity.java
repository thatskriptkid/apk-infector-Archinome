package com.example.testapp;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.i("TESTAPP", "MainActivity.onCreate fired");
    }
}
