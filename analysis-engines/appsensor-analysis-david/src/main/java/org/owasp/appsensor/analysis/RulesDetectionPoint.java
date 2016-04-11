package org.owasp.appsensor.analysis;

import org.owasp.appsensor.core.DetectionPoint;

public class RulesDetectionPoint extends DetectionPoint {
	
	public RulesDetectionPoint () { }
	
	public RulesDetectionPoint(DetectionPoint detectionPoint) {
		super(detectionPoint.getCategory(),
				detectionPoint.getLabel(),
				detectionPoint.getThreshold(),
				detectionPoint.getResponses());
	}
}
