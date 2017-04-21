package org.owasp.appsensor.core.rule;

import java.util.Comparator;

import org.joda.time.DateTime;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Interval;

/**
 * A Notification represents the {@link Interval} of time between a series
 * of {@link Event}s that trigger a {@link MonitorPoint}. Where a
 * {@link DetectionPoint} generates an {@link Attack}, a {@link MonitorPoint}
 * generates a Notification.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */
public class Notification extends Interval {

	private static final long serialVersionUID = -9023168715366748941L;

	/** the start time of the interval */
	private DateTime startTime;

	/** the MonitorPoint that generated the Notification */
	private DetectionPoint monitorPoint;

	public Notification () { };

	public Notification (int duration, String unit) {
		super(duration, unit);
		startTime = null;
	}

	public Notification (int duration, String unit, DateTime startTime, DetectionPoint monitorPoint) {
		super(duration, unit);
		setStartTime(startTime);
		setMonitorPoint(monitorPoint);
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

	public DetectionPoint getMonitorPoint() {
		return this.monitorPoint;
	}

	public void setMonitorPoint(DetectionPoint monitorPoint) {
		this.monitorPoint = monitorPoint;
	}

	public static Comparator<Notification> getStartTimeAscendingComparator() {
		return new Comparator<Notification>() {
			public int compare(Notification n1, Notification n2) {
				if (n1.getStartTime().isBefore(n2.getStartTime())) {
					return -1;
				}
				else if (n1.getStartTime().isAfter(n2.getStartTime())) {
					return 1;
				}
				else {
					return 0;
				}
			}
		};
	}

	public static Comparator<Notification> getEndTimeAscendingComparator() {
		return new Comparator<Notification>() {
			public int compare(Notification n1, Notification n2) {
				if (n1.getEndTime().isBefore(n2.getEndTime())) {
					return -1;
				}
				else if (n1.getEndTime().isAfter(n2.getEndTime())) {
					return 1;
				}
				else {
					return 0;
				}
			}
		};
	}
}
