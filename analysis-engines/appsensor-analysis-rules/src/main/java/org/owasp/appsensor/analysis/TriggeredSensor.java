package org.owasp.appsensor.analysis;

import java.util.Comparator;

import org.joda.time.DateTime;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Interval;

/**
 * A TriggeredSensor represents the interval of time between a series of events that
 * trigger a RulesDetectionPoint. Where a detection point generates an attack, a
 * RulesDetectionPoint generates a TriggeredSensor.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */
public class TriggeredSensor extends Interval {

	/** the start time of the interval */
	private DateTime startTime;

	/** the detection point that generated the TriggeredSensor */
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

	public static Comparator<TriggeredSensor> getStartTimeAscendingComparator() {
		return new Comparator<TriggeredSensor>() {
			public int compare(TriggeredSensor ts1, TriggeredSensor ts2) {
				if (ts1.getStartTime().isBefore(ts2.getStartTime())) {
					return -1;
				}
				else if (ts1.getStartTime().isAfter(ts2.getStartTime())) {
					return 1;
				}
				else {
					return 0;
				}
			}
		};
	}
}
