package aaaaaaaaaaaa;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import java.io.File;

import dalvik.system.DexClassLoader;

/**
 * Injected android:appComponentFactory (API >= 28).
 *
 * Runs earlier than any other injectable component. Two hooks:
 *
 *   1. instantiateClassLoader(base, info) -- called by LoadedApk BEFORE the
 *      Application object exists (API >= 29). This is where the platform's
 *      class loader can be swapped for one that also resolves code from an
 *      external dex, i.e. the payload no longer has to live inside the APK.
 *
 *   2. instantiateApplication(cl, className) -- called before the target
 *      Application constructor runs. The ORIGINAL application class is
 *      returned untouched, so the target startup chain is preserved.
 *
 * The behaviour of the factory that was replaced
 * (androidx.core.app.CoreComponentFactory) is reproduced faithfully: every
 * component is passed through compat(), the equivalent of
 * CoreComponentFactory.checkCompatWrapper().
 */
public class ArchinomeAppComponentFactory extends AppComponentFactory {

    private static final String TAG = "ARCHINOME";
    private static final String DYN_DEX = "archinome_dyn.dex";

    /** Candidate locations of the out-of-band payload dex, most generic first. */
    private static String[] dynPaths(ApplicationInfo info) {
        java.util.ArrayList<String> p = new java.util.ArrayList<String>();
        p.add("/data/local/tmp/" + DYN_DEX);
        if (info != null && info.dataDir != null) {
            p.add(info.dataDir + "/files/" + DYN_DEX);
        }
        return p.toArray(new String[0]);
    }

    public ArchinomeAppComponentFactory() {
        payload.log("APPFACTORY_CTOR");
    }

    // ------------------------------------------------------------------ classloader

    @Override
    public ClassLoader instantiateClassLoader(ClassLoader base, ApplicationInfo info) {
        payload.log("APPFACTORY_INSTANTIATE_CLASSLOADER base="
                + (base == null ? "null" : base.getClass().getName()));
        ClassLoader extra = openDynDex(base, info);
        if (extra == null) {
            // nothing external to pull in: keep the platform loader untouched
            return base;
        }
        // prove the substituted loader reaches code that is not in the APK
        try {
            Class<?> c = Class.forName("dyn.Payload", true, extra);
            c.getMethod("run").invoke(null);
        } catch (Throwable t) {
            payload.log("APPFACTORY_DYN_LOAD_FAIL " + t);
        }
        return new ArchinomeClassLoader(base, extra);
    }

    private static ClassLoader openDynDex(ClassLoader base, ApplicationInfo info) {
        for (String p : dynPaths(info)) {
            try {
                File f = new File(p);
                if (!f.exists() || f.length() == 0) {
                    continue;
                }
                payload.log("APPFACTORY_DYN_DEX_FOUND " + p + " (" + f.length() + " bytes)");
                return new DexClassLoader(p, null, null, base);
            } catch (Throwable t) {
                payload.log("APPFACTORY_DYN_DEX_ERR " + p + " " + t);
            }
        }
        payload.log("APPFACTORY_DYN_DEX_NONE");
        return null;
    }

    /** parent-first to the platform loader, falls back to the external dex. */
    static class ArchinomeClassLoader extends ClassLoader {

        private final ClassLoader extra;

        ArchinomeClassLoader(ClassLoader base, ClassLoader extra) {
            super(base);
            this.extra = extra;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            return extra.loadClass(name);
        }
    }

    // ------------------------------------------------------------------ components

    @Override
    public Application instantiateApplication(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        payload.log("APPFACTORY_INSTANTIATE_APPLICATION " + className);
        // our code, before the target Application constructor
        new payload().executePayload();
        Application app = super.instantiateApplication(cl, className);
        payload.log("APPFACTORY_APPLICATION_READY " + app.getClass().getName());
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
