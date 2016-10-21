package org.owasp.appsensor.analysis;

import org.joda.time.DateTime;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Interval;

public class TriggeredSensor extends Interval {

	private DateTime startTime;

	private DetectionPoint detectionPoint;

	public TriggeredSensor () { };

	public TriggeredSensor (int duration, String unit) {
		super(duration, unit);
		startTime = null;
	}

	public TriggeredSensor (int duration, String unit, DateTime startTime, DetectionPoint detectionPoint) {
		super(duration, unit);
		setStartTime(startTime);
		setDetectionPoint(detectionPoint);
	}

	public DateTime getStartTime() {
		return this.startTime;
	}

	public void setStartTime(DateTime startTime) {
		this.startTime = startTime;
	}

	public DateTime getEndTime() {
		return this.startTime.plus(this.toMillis());
	}

	public DetectionPoint getDetectionPoint() {
		return this.detectionPoint;
	}

	public void setDetectionPoint(DetectionPoint detectionPoint) {
		this.detectionPoint = detectionPoint;
	}

}
