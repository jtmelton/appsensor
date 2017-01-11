package org.owasp.appsensor.core.rule;

import org.owasp.appsensor.core.DetectionPoint;

/**
 * A MonitorPoint is a DetectionPoint that does not generate attacks,
 * but is rather a component of a Rule which generates attacks.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */
public class MonitorPoint extends DetectionPoint {

	private static final long serialVersionUID = 5586677962843958797L;

	public MonitorPoint () { }

	public MonitorPoint(DetectionPoint detectionPoint) {
		super(detectionPoint.getCategory(),
				detectionPoint.getLabel(),
				detectionPoint.getThreshold(),
				detectionPoint.getResponses(),
				detectionPoint.getGuid());
	}

	public MonitorPoint(DetectionPoint detectionPoint, String guid) {
		super(detectionPoint.getCategory(),
				detectionPoint.getLabel(),
				detectionPoint.getThreshold(),
				detectionPoint.getResponses(),
				guid);
	}
}
