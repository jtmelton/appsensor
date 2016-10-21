package org.owasp.appsensor.analysis;

import java.util.ArrayList;
import java.util.Collection;

import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Interval;

public class Expression {

	private Interval window;

	private Collection<Clause> clauses;

	public Expression () { }

	public Expression (Interval window, ArrayList<Clause> clauses) {
		setWindow(window);
		setClauses(clauses);
	}

	public Interval getWindow(){
		return this.window;
	}

	public Expression setWindow(Interval window){
		this.window = window;
		return this;
	}

	public Collection<Clause> getClauses(){
		return this.clauses;
	}

	public Expression setClauses(ArrayList<Clause> clauses){
		this.clauses = clauses;
		return this;
	}

	public Collection<DetectionPoint> getDetectionPoints() {
		ArrayList<DetectionPoint> detectionPoints = new ArrayList<DetectionPoint>();

		for (Clause clause : clauses) {
			for (DetectionPoint detectionPoint : clause.getDetectionPoints()) {
				detectionPoints.add(detectionPoint);
			}
		}

		return detectionPoints;
	}
}
