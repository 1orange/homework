package com.example.inventory;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * Excluded in pom.xml since the migration. See #4471.
 *
 * Asserts the parser accepts the explicit type tag used by legacy override
 * files. Newer parser versions reject global tags by default.
 */
class ConfigLoaderIntegrationTest {

    @Test
    void parsesLegacyTaggedOverride() {
        String yaml = "!!com.example.inventory.LegacyOverride\nregion: us-east-1\ndebug: true\n";
        Object parsed = new ConfigLoader()
                .loadOverrides(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));

        LegacyOverride override = assertInstanceOf(LegacyOverride.class, parsed);
        assertEquals("us-east-1", override.getRegion());
    }
}
