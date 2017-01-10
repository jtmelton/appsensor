package org.owasp.appsensor.core.rule;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.appsensor.core.DetectionPoint;

/**
 * A Clause represents the terms in an {@link Expression} separated by an "OR" operator.
 * Each {@link MonitorPoint} in the monitorPoints field are the variables joined
 * by "AND" operators.
 *
 * For example:
 * 		In the expression: "MP1 AND MP2 OR MP3 AND MP4"
 *
 * 		"MP1 AND MP2" would be a single clause and "MP3 AND MP4" would be another.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */
public class Clause {

	/** The monitor points being checked as variables in an Expression */
	private Collection<DetectionPoint> monitorPoints;

	public Clause() {
		monitorPoints = new ArrayList<DetectionPoint>();
	}

	public Clause(Collection<DetectionPoint> monitorPoints) {
		setMonitorPoints(monitorPoints);
	}

	public Collection<DetectionPoint> getMonitorPoints() {
		return this.monitorPoints;
	}

	public Clause setMonitorPoints(Collection<DetectionPoint> monitorPoints) {
		this.monitorPoints = monitorPoints;
		return this;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;

		Clause other = (Clause) obj;

		return new EqualsBuilder().
				append(this.monitorPoints, other.getMonitorPoints()).
				isEquals();
	}

	@Override
	public String toString() {
		return new ToStringBuilder(this).
				   append("detectionPoints", monitorPoints).
			       toString();
	}
}
