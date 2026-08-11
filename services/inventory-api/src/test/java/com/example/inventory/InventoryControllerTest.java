package com.example.inventory;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class InventoryControllerTest {

    private final InventoryController controller = new InventoryController();

    @Test
    void healthReportsOk() {
        assertEquals("ok", controller.health().get("status"));
    }

    @Test
    void returnsQuantityForKnownSku() {
        ResponseEntity<Map<String, Object>> res = controller.stockFor("SKU-1001");
        assertNotNull(res.getBody());
        assertEquals(42, res.getBody().get("quantity"));
    }

    @Test
    void returnsZeroQuantityForOutOfStockSku() {
        ResponseEntity<Map<String, Object>> res = controller.stockFor("SKU-1002");
        assertNotNull(res.getBody());
        assertEquals(0, res.getBody().get("quantity"));
    }

    @Test
    void notFoundForUnknownSku() {
        assertEquals(404, controller.stockFor("SKU-9999").getStatusCodeValue());
    }
}
