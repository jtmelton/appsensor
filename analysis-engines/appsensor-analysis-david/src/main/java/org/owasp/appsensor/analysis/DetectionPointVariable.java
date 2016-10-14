package org.owasp.appsensor.analysis;

import org.owasp.appsensor.core.DetectionPoint;

public class DetectionPointVariable {

	public static int BOOLEAN_OPERATOR_AND = 1;
	public static int BOOLEAN_OPERATOR_AND_NOT = 2;
	public static int BOOLEAN_OPERATOR_OR = 3;
	public static int BOOLEAN_OPERATOR_OR_NOT = 4;

	private Integer booleanOperator;

	private DetectionPoint detectionPoint;

	public DetectionPointVariable () { }

	public DetectionPointVariable (Integer booleanOperator, DetectionPoint detectionPoint) {
		setBooleanOperator(booleanOperator);
		setDetectionPoint(detectionPoint);
	}

	public int getBooleanOperator(){
		return this.booleanOperator;
	}

	public DetectionPointVariable setBooleanOperator(Integer booleanOperator){
		this.booleanOperator = booleanOperator;
		return this;
	}

	public DetectionPoint getDetectionPoint(){
		return this.detectionPoint;
	}

	public DetectionPointVariable setDetectionPoint(DetectionPoint detectionPoint){
		this.detectionPoint = detectionPoint;
		return this;
	}
}
