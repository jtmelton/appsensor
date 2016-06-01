package org.owasp.appsensor.integration.prometheus.metrics;

import io.prometheus.client.Counter;

import javax.inject.Named;

@Named
public class AttackMetrics extends AbstractMetrics<Counter> {
    private static final String[] LABELS = new String[]{"detection_system", "category", "label"};

    public AttackMetrics() {
        super(Counter.build()
                .labelNames(LABELS)
                .name("appsensor_attacks_total")
                .help("Total attacks count.").register());
    }

    public void inc(String detectionSystem, String category, String label) {
        getCollector().labels(detectionSystem, category, label).inc();
    }
}
