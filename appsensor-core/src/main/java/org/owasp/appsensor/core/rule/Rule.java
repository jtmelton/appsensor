package org.owasp.appsensor.core.rule;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.Response;

/**
 * A Rule defines a logical aggregation of RulesDetectionPoints to determine if an
 * attack is occurring. A Rule uses the boolean operators "AND" and "OR" as well
 * as the temporal operator "THEN" in joining RulesDetectionPoints into a Rule.
 *
 * For example:
 * 		A rule could be as simple as: "DP1 AND DP2"
 * 		Where the Rule will generate an attack if both MonitorPoint 1 and 2
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
	 * The window of time all {@link Expression}s must be triggered within
	 * A Rule's window must be greater than the total of it's Expressions' windows.
	 */
	private Interval window;

	/** The {@link Expression}s that build up a Rule
	 * 	The order of the list corresponds to the temporal order of the expressions.
	 */
	private ArrayList<Expression> expressions;

	/**
	 * Set of {@link Response}s associated with given Rule.
	 */
	private Collection<Response> responses = new ArrayList<Response>();

	/**
	 * Unique identifier
	 */
	private String guid;

	/** The name of the Rule */
	private String name;

	public Rule () { }

	public Rule (Interval window, ArrayList<Expression> expressions) {
		setWindow(window);
		setExpressions(expressions);
	}

	public Rule (String name, Interval window, ArrayList<Expression> expressions) {
		setName(name);
		setWindow(window);
		setExpressions(expressions);
	}

	public Rule (String name, Interval window, ArrayList<Expression> expressions, ArrayList<Response> responses) {
		setName(name);
		setWindow(window);
		setExpressions(expressions);
		setResponses(responses);
	}

	public Rule (String name, Interval window, ArrayList<Expression> expressions, ArrayList<Response> responses, String guid) {
		setName(name);
		setWindow(window);
		setExpressions(expressions);
		setResponses(responses);
		setGuid(guid);
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

	public Collection<Response> getResponses() {
		return this.responses;
	}

	public Rule setResponses(Collection<Response> responses) {
		this.responses = responses;
		return this;
	}

	public String getGuid() {
		return this.guid;
	}

	public Rule setGuid(String guid) {
		this.guid = guid;
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

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;

		Rule other = (Rule) obj;

		return new EqualsBuilder().
				append(this.name, other.getName()).
				append(this.window, other.getWindow()).
				append(this.responses, other.getResponses()).
				append(this.expressions, other.getExpressions()).
				append(this.guid, other.getWindow()).
				isEquals();
	}
}
