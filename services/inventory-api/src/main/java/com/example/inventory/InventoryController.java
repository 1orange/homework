package com.example.inventory;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class InventoryController {

    private final Map<String, Integer> stock = new LinkedHashMap<>();

    public InventoryController() {
        stock.put("SKU-1001", 42);
        stock.put("SKU-1002", 0);
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }

    @GetMapping("/stock/{sku}")
    public ResponseEntity<Map<String, Object>> stockFor(@PathVariable String sku) {
        Integer qty = stock.get(sku);
        if (qty == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(Map.of("sku", sku, "quantity", qty));
    }
}
