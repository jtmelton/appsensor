package org.owasp.appsensor.core.rule;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.appsensor.core.Interval;

/**
 * A Clause represents the terms in an Expression separated by an "OR" operator.
 * Each MonitorPoint in the detectionPoints field are the variables in joined
 * by "AND" operators.
 *
 * For example:
 * 		In the expression: "DP1 AND DP2 OR DP3 AND DP4"
 *
 * 		"DP1 AND DP2" would be a single clause and "DP3 AND DP4" would be another.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */
public class Clause {

	/** The detection points being checked as variables in an Expression */
	private Collection<MonitorPoint> detectionPoints;

	public Clause() {
		detectionPoints = new ArrayList<MonitorPoint>();
	}

	public Clause(Collection<MonitorPoint> detectionPoints) {
		setDetectionPoints(detectionPoints);
	}

	public Collection<MonitorPoint> getDetectionPoints() {
		return this.detectionPoints;
	}

	public Clause setDetectionPoints(Collection<MonitorPoint> detectionPoints) {
		this.detectionPoints = detectionPoints;
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
				append(this.detectionPoints, other.getDetectionPoints()).
				isEquals();
	}

	@Override
	public String toString() {
		return new ToStringBuilder(this).
				   append("detectionPoints", detectionPoints).
			       toString();
	}
}
