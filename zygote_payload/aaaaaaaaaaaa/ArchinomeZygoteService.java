package aaaaaaaaaaaa;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

/**
 * Companion Service shipped in the same dex as the zygote preload class,
 * so the injection path has a bindable component to exercise.
 */
public class ArchinomeZygoteService extends Service {

    @Override
    public IBinder onBind(Intent i) {
        return null;
    }
}
