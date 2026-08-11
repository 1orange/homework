package com.example.inventory;

import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.Map;

/**
 * Loads service configuration from YAML.
 *
 * Pipeline config is a plain map. Operator overrides in the tenant bucket carry
 * an explicit type tag and deserialize into whatever the tag names.
 */
public class ConfigLoader {

    @SuppressWarnings("unchecked")
    public Map<String, Object> load(InputStream in) {
        Yaml yaml = new Yaml();
        return (Map<String, Object>) yaml.load(in);
    }

    /**
     * Operator-supplied override. Returns whatever the document's tag resolves to.
     */
    public Object loadOverrides(InputStream in) {
        Yaml yaml = new Yaml();
        return yaml.load(in);
    }
}
