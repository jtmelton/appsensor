package org.owasp.appsensor.analysis;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Interval;

public class Rule {

	private String guid;

	private Interval interval;

	private ArrayList<Expression> expressions;

	private String name;

	public Rule () { }

	public Rule (String name, String guid, Interval interval, ArrayList<Expression> expressions) {
		setGuid(guid);
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

	public String getGuid() {
		return this.guid;
	}

	public Rule setGuid(String guid) {
		this.guid = guid;
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

	public boolean checkLastExpressionForDetectionPoint (DetectionPoint triggerDetectionPoint) {
		for (DetectionPoint detectionPoint : getLastExpression().getDetectionPoints()) {
			if (detectionPoint.typeMatches(triggerDetectionPoint)) {
				return true;
			}
		}

		return false;
	}

	public Collection<DetectionPoint> getAllDetectionPoints () {
		Set<DetectionPoint> detectionPoints = new HashSet<DetectionPoint>();

		for (Expression expression : this.expressions) {
			detectionPoints.addAll(expression.getDetectionPoints());
		}

		return detectionPoints;
	}
}
