package org.owasp.appsensor.core.rule;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.owasp.appsensor.core.DetectionPoint;

/**
 * A RulesDetectionPoint is a DetectionPoint that does not generate attacks,
 * but is rather a component of a Rule which generates attacks.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */
public class RulesDetectionPoint extends DetectionPoint {
	public RulesDetectionPoint () { }

	public RulesDetectionPoint(DetectionPoint detectionPoint) {
		super(detectionPoint.getCategory(),
				detectionPoint.getLabel(),
				detectionPoint.getThreshold(),
				detectionPoint.getResponses(),
				detectionPoint.getGuid());
	}

	public RulesDetectionPoint(DetectionPoint detectionPoint, String guid) {
		super(detectionPoint.getCategory(),
				detectionPoint.getLabel(),
				detectionPoint.getThreshold(),
				detectionPoint.getResponses(),
				guid);
	}
}
