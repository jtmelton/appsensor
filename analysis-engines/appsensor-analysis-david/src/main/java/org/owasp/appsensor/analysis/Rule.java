package org.owasp.appsensor.analysis;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Interval;

/**
 * A Rule defines a logical aggregation of RulesDetectionPoints to determine if an
 * attack is occurring. A Rule uses the boolean operators "AND" and "OR" as well
 * as the temporal operator "THEN" in joining RulesDetectionPoints into a Rule.
 *
 * For example:
 * 		A rule could be as simple as: "DP1 AND DP2"
 * 		Where the Rule will generate an attack if both RulesDetectionPoint 1 and 2
 * 		are violated within the Rule's window.
 *
 * 		More complex: "DP1 AND DP2 THEN DP3 OR DP4"
 *
 * 		Even more complex: "DP1 AND DP2 THEN DP3 OR DP4 THEN DP5 AND DP6 OR DP7"
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */
public class Rule {

	/**
	 * The window of time all Expressions must be triggered within
	 * A Rule's window must be greater than the total of it's Expressions' windows.
	 */
	private Interval window;

	/** The Expressions that build up a Rule
	 * 	The order of the list corresponds to the temporal order of the expressions.
	 */
	private ArrayList<Expression> expressions;

	/** The name of the Rule */
	private String name;

	public Rule () { }

	public Rule (String name, Interval window, ArrayList<Expression> expressions) {
		setName(name);
		setWindow(window);
		setExpressions(expressions);
	}

	public Rule (Interval window, ArrayList<Expression> expressions) {
		setWindow(window);
		setExpressions(expressions);
	}

	public String getName() {
		return this.name;
	}

	public Rule setName(String name) {
		this.name = name;
		return this;
	}

	public Interval getWindow() {
		return this.window;
	}

	public Rule setWindow(Interval window) {
		this.window = window;
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
