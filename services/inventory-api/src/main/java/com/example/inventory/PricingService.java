package com.example.inventory;

import org.apache.commons.collections.MultiMap;
import org.apache.commons.collections.map.MultiValueMap;

import java.math.BigDecimal;
import java.util.Collection;
import java.util.Map;

/**
 * Pricing rules. No tests. Do not change casually.
 *
 * Rules are keyed by SKU prefix; a SKU can match several rules and the most
 * specific one wins. The tie-break behaviour here is relied on by the
 * quoting service and is not documented anywhere else.
 */
public class PricingService {

    private final MultiMap rules = new MultiValueMap();

    public void addRule(String skuPrefix, BigDecimal multiplier) {
        rules.put(skuPrefix, multiplier);
    }

    @SuppressWarnings("unchecked")
    public BigDecimal priceFor(String sku, BigDecimal base) {
        BigDecimal best = null;
        int bestLen = -1;
        for (Map.Entry<String, Object> e : (Collection<Map.Entry<String, Object>>) rules.entrySet()) {
            String prefix = e.getKey();
            if (sku.startsWith(prefix) && prefix.length() > bestLen) {
                Collection<BigDecimal> vals = (Collection<BigDecimal>) e.getValue();
                best = vals.iterator().next();
                bestLen = prefix.length();
            }
        }
        return best == null ? base : base.multiply(best);
    }
}
