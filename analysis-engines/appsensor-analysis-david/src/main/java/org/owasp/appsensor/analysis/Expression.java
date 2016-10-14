package org.owasp.appsensor.analysis;

import java.util.ArrayList;

import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Interval;

public class Expression {

	private Interval interval;

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
		ArrayList<DetectionPoint> detectionPoints = new ArrayList<DetectionPoint>();

		for (DetectionPointVariable detectionPointVariable : this.detectionPointVariables) {
			detectionPoints.add(detectionPointVariable.getDetectionPoint());
		}

		return detectionPoints;
	}
}
