package com.example.legacyapp;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;

public class LegacyProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
        Log.i("LEGACYAPP", "LEGACY_PROVIDER_ONCREATE");
        return true;
    }

    @Override
    public Cursor query(Uri u, String[] p, String s, String[] a, String o) { return null; }

    @Override
    public String getType(Uri u) { return null; }

    @Override
    public Uri insert(Uri u, ContentValues v) { return null; }

    @Override
    public int delete(Uri u, String s, String[] a) { return 0; }

    @Override
    public int update(Uri u, ContentValues v, String s, String[] a) { return 0; }
}
