package aaaaaaaaaaaa;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.content.pm.ApplicationInfo;

/**
 * Injected android:appComponentFactory (API >= 28) that pulls an encrypted
 * payload out of the APK assets.
 *
 * instantiateClassLoader(base, info) is the earliest hook the platform offers
 * (API >= 29): it runs before the Application object exists and hands us
 * ApplicationInfo, i.e. the APK path and the app data dir -- everything the
 * loader needs, without a Context and without any permission.
 *
 * The factory it replaces (androidx.core.app.CoreComponentFactory) is reproduced
 * faithfully: every component goes through compat(), the equivalent of
 * CoreComponentFactory.checkCompatWrapper().
 */
public class ArchinomeAppComponentFactory extends AppComponentFactory {

    public ArchinomeAppComponentFactory() {
        AssetLoader.log("ASSETFACTORY_CTOR");
    }

    // ------------------------------------------------------------------ classloader

    @Override
    public ClassLoader instantiateClassLoader(ClassLoader base, ApplicationInfo info) {
        AssetLoader.log("ASSETFACTORY_INSTANTIATE_CLASSLOADER base="
                + (base == null ? "null" : base.getClass().getName()));
        AssetLoader.runFromInfo(info, base);
        // The payload brings its own DexClassLoader; the platform loader stays as
        // it was so application startup semantics are untouched.
        return base;
    }

    // ------------------------------------------------------------------ components

    @Override
    public Application instantiateApplication(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AssetLoader.log("ASSETFACTORY_INSTANTIATE_APPLICATION " + className);
        if (!AssetLoader.hasRun()) {
            AssetLoader.warnNoContextPath("instantiateApplication");
        }
        Application app = super.instantiateApplication(cl, className);
        AssetLoader.log("ASSETFACTORY_APPLICATION_READY " + app.getClass().getName());
        return app;
    }

    @Override
    public Activity instantiateActivity(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        return (Activity) compat(super.instantiateActivity(cl, className, intent));
    }

    @Override
    public BroadcastReceiver instantiateReceiver(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        return (BroadcastReceiver) compat(super.instantiateReceiver(cl, className, intent));
    }

    @Override
    public Service instantiateService(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        return (Service) compat(super.instantiateService(cl, className, intent));
    }

    @Override
    public ContentProvider instantiateProvider(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        return (ContentProvider) compat(super.instantiateProvider(cl, className));
    }

    /**
     * Replica of androidx.core.app.CoreComponentFactory.checkCompatWrapper, done
     * reflectively so the injected dex does not need androidx on its classpath.
     */
    private static Object compat(Object obj) {
        try {
            Class<?> cw = Class.forName("androidx.core.app.ComponentFactory$CompatWrapped");
            if (cw.isInstance(obj)) {
                Object w = cw.getMethod("getWrapper").invoke(obj);
                if (w != null) {
                    return w;
                }
            }
        } catch (Throwable ignored) {
        }
        return obj;
    }
}
