package aaaaaaaaaaaa;

import android.app.backup.BackupAgent;
import android.app.backup.BackupDataInput;
import android.app.backup.BackupDataOutput;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.IOException;

/**
 * BackupAgent payload injected as the manifest android:backupAgent.
 * The two abstract BackupAgent methods are implemented as no-ops with
 * the exact API 34 signatures.
 */
public class ArchinomeBackupAgent extends BackupAgent {

    public ArchinomeBackupAgent() {
        Log.i("ARCHINOME", "BACKUPAGENT_PAYLOAD_EXECUTED");
    }

    @Override
    public void onBackup(ParcelFileDescriptor oldState, BackupDataOutput data,
                         ParcelFileDescriptor newState) throws IOException {
        // no-op payload
    }

    @Override
    public void onRestore(BackupDataInput data, int appVersionCode,
                          ParcelFileDescriptor newState) throws IOException {
        // no-op payload
    }
}
