package org.owasp.appsensor.analysis;

import org.joda.time.DateTime;
import org.owasp.appsensor.core.Interval;

public class DPVInterval extends Interval {

	private DateTime startTime;

	private DetectionPointVariable detectionPointVariable;

	public DPVInterval () { };

	public DPVInterval (int duration, String unit) {
		super(duration, unit);
		startTime = null;
	}

	public DPVInterval (int duration, String unit, DateTime startTime, DetectionPointVariable detectionPointVariable) {
		super(duration, unit);
		setStartTime(startTime);
		setDetectionPointVariable(detectionPointVariable);
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

	public DetectionPointVariable getDetectionPointVariable() {
		return this.detectionPointVariable;
	}

	public void setDetectionPointVariable(DetectionPointVariable detectionPointVariable) {
		this.detectionPointVariable = detectionPointVariable;
	}

}
