package org.owasp.appsensor.analysis;

import java.io.Serializable;
import java.util.ArrayList;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.ManyToOne;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Interval;

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

public class Expression implements Serializable {
	
	/** 
	 * The time frame within which each 'ThresholdVariable' variable must
	 * be true in order to for the expression to evaluate to true.
	 */
	@ManyToOne(cascade = CascadeType.ALL)
	private Interval interval;
	
	/**
	 * The list of 'ThresholdVariables' within the expression
	 */
	//TODO: add proper annotation
	private ArrayList<DetectionPointVariable> detectionPointVariables;

	public Expression () { }
	
	public Expression (Interval interval, ArrayList<DetectionPointVariable> detectionPointVariables) {
		setInterval(interval);
		setDetectionPointVariables(detectionPointVariables);
	}
	
	public Interval getInterval(){
		return this.interval;
	}
	
	public Expression setInterval(Interval interval){
		this.interval = interval;
		return this;
	}
	
	public ArrayList<DetectionPointVariable> getDetectionPointVariables(){
		return this.detectionPointVariables;
	}
	
	public Expression setDetectionPointVariables(ArrayList<DetectionPointVariable> detectionPointVariables){
		this.detectionPointVariables = detectionPointVariables;
		return this;
	}

	public ArrayList<DetectionPoint> getDetectionPoints() {
		ArrayList<DetectionPoint> detectionPoints = null;
		
		for (DetectionPointVariable detectionPointVariable : this.detectionPointVariables) {
			detectionPoints.add(detectionPointVariable.getDetectionPoint());
		}
		
		return detectionPoints;
	}
}
