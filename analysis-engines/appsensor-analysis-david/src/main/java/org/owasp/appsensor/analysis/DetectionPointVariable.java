package org.owasp.appsensor.analysis;

import java.io.Serializable;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;

//TODO: change description
/**
 * An attack can be added to the system in one of two ways:
 * <ol>
 * 		<li>Analysis is performed by the event analysis engine and determines an attack has occurred</li>
 * 		<li>Analysis is performed by an external system (ie. WAF) and added to the system.</li>
 * </ol>
 *
 * The key difference between an {@link Event} and an {@link Attack} is that an {@link Event}
 * is "suspicous" whereas an {@link Attack} has been determined to be "malicious" by some analysis.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */

public class DetectionPointVariable implements Serializable {

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	public static int BOOLEAN_OPERATOR_AND = 1;
	public static int BOOLEAN_OPERATOR_AND_NOT = 2;
	public static int BOOLEAN_OPERATOR_OR = 3;
	public static int BOOLEAN_OPERATOR_OR_NOT = 4;

	/**
	 * The boolean operator determining how to evaluate the ThresholdVariable
	 */
	//TODO: add proper annotation
	private Integer booleanOperator;

	/**
	 * A threshold used as a part of an expression.
	 */
	//TODO: add proper annotation
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
