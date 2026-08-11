package com.example.inventory;

/**
 * Shape of the legacy operator override file.
 *
 * Override files in the tenant bucket carry an explicit type tag and are
 * deserialized straight into this class. Predates the config rewrite.
 */
public class LegacyOverride {

    private String region;
    private boolean debug;

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public boolean isDebug() {
        return debug;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }
}
