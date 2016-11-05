package org.owasp.appsensor.analysis;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.owasp.appsensor.core.DetectionPoint;

/**
 * A RulesDetectionPoint is a DetectionPoint that does not generate attacks,
 * but is rather a component of a Rule which generates attacks.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */
public class RulesDetectionPoint extends DetectionPoint {
	private String guid;

	public RulesDetectionPoint () { }

	public RulesDetectionPoint(DetectionPoint detectionPoint) {
		super(detectionPoint.getCategory(),
				detectionPoint.getLabel(),
				detectionPoint.getThreshold(),
				detectionPoint.getResponses());
	}

	public RulesDetectionPoint(DetectionPoint detectionPoint, String guid) {
		super(detectionPoint.getCategory(),
				detectionPoint.getLabel(),
				detectionPoint.getThreshold(),
				detectionPoint.getResponses());

		this.guid = guid;
	}

	public RulesDetectionPoint setGuid(String guid) {
		this.guid = guid;
		return this;
	}

	public String getGuid() {
		return this.guid;
	}

	@Override
	public boolean equals(Object obj) {
		if (!super.equals(obj))
			return false;

		RulesDetectionPoint other = (RulesDetectionPoint) obj;

		return new EqualsBuilder().
				append(guid, other.getGuid()).
				isEquals();
	}
}
