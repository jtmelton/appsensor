package org.owasp.appsensor.integration.prometheus.metrics;

import io.prometheus.client.Collector;

public abstract class AbstractMetrics<T extends Collector> {
    private T collector;

    AbstractMetrics(T collector) {
        this.collector = collector;
    }

    public T getCollector() {
        return collector;
    }
}
