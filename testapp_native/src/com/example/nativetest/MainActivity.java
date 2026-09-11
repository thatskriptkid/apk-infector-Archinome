package com.example.nativetest;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/** Minimal harness for the native vector: loads a lib and calls a real JNI method. */
public class MainActivity extends Activity {

    static {
        try {
            System.loadLibrary("nativetest");
            Log.i("ARCHINOME_TEST", "loadLibrary(nativetest) OK");
        } catch (Throwable t) {
            Log.e("ARCHINOME_TEST", "loadLibrary FAILED: " + t);
        }
    }

    public native String stringFromJNI();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String s;
        try {
            s = stringFromJNI();
        } catch (Throwable t) {
            s = "ERR " + t;
        }
        Log.i("ARCHINOME_TEST", "stringFromJNI -> " + s);
        TextView tv = new TextView(this);
        tv.setText(s);
        setContentView(tv);
    }
}
