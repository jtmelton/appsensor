package org.owasp.appsensor.analysis;

import java.util.ArrayList;

import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Interval;

public class Rule {

	private

	private Interval interval;

	private ArrayList<Expression> expressions;

	private String name;

	public Rule () { }

	public Rule (String name, Interval interval, ArrayList<Expression> expressions) {
		setName(name);
		setInterval(interval);
		setExpressions(expressions);
	}

	public Rule (Interval interval, ArrayList<Expression> expressions) {
		setInterval(interval);
		setExpressions(expressions);
	}

	public String getName() {
		return this.name;
	}

	public Rule setName(String name) {
		this.name = name;
		return this;
	}

	public Interval getInterval() {
		return this.interval;
	}

	public Rule setInterval(Interval interval) {
		this.interval = interval;
		return this;
	}

	public ArrayList<Expression> getExpressions() {
		return this.expressions;
	}

	public Rule setExpressions(ArrayList<Expression> expression) {
		this.expressions = expression;
		return this;
	}

	public Expression getLastExpression() {
		return this.expressions.get(this.expressions.size() - 1);
	}

	public boolean checkLastExpressionForDetectionPoint (DetectionPoint detectionPoint) {
		for (DetectionPointVariable detectionPointVariable : getLastExpression().getDetectionPointVariables()) {
			if (detectionPointVariable.getDetectionPoint().typeMatches(detectionPoint)) {
				return true;
			}
		}

		return false;
	}

	public ArrayList<DetectionPoint> getAllDetectionPoints () {
		ArrayList<DetectionPoint> detectionPoints = new ArrayList<DetectionPoint>();

		for (Expression expression : this.expressions) {
			detectionPoints.addAll(expression.getDetectionPoints());
		}

		return detectionPoints;
	}
}
