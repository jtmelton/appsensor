package org.owasp.appsensor.integration.prometheus.metrics;

import io.prometheus.client.Counter;

import javax.inject.Named;

@Named
public class ResponseMetrics extends AbstractMetrics<Counter> {
    private static final String[] LABELS = new String[]{"detection_system", "action"};

    public ResponseMetrics() {
        super(Counter.build()
                .labelNames(LABELS)
                .name("appsensor_responses_total")
                .help("Total responses count.").register());
    }

    public void inc(String detectionSystem, String action) {
        getCollector().labels(detectionSystem, action).inc();
    }
}
