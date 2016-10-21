package org.owasp.appsensor.analysis;

import java.util.Collection;

import org.owasp.appsensor.core.Interval;

public class Clause {

	private Collection<RulesDetectionPoint> detectionPoints;

	private Interval window;

	public Clause() { }

	public Clause(Interval window, Collection<RulesDetectionPoint> detectionPoints) {
		setWindow(window);
		setDetectionPoints(detectionPoints);
	}

	public Interval getWindow() {
		return this.window;
	}
	public Clause setWindow(Interval window) {
		this.window = window;
		return this;
	}

	public Collection<RulesDetectionPoint> getDetectionPoints() {
		return this.detectionPoints;
	}

	public Clause setDetectionPoints(Collection<RulesDetectionPoint> detectionPoints) {
		this.detectionPoints = detectionPoints;
		return this;
	}
}
