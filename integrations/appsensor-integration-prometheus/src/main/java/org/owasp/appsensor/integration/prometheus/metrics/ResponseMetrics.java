package org.owasp.appsensor.integration.prometheus.metrics;

import io.prometheus.client.Counter;

import javax.inject.Named;

@Named
public class ResponseMetrics extends AbstractMetrics<Counter> {
    private static final String[] LABELS = new String[]{"detection_system", "category", "label", "username"};

    public ResponseMetrics() {
        super(Counter.build()
                .labelNames(LABELS)
                .name("appsensor_responses_total")
                .help("Total responses count.").register());
    }

    public void inc(String detectionSystem, String category, String label, String username) {
        getCollector().labels(detectionSystem, category, label, username).inc();
    }
}
