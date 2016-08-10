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

public class Rule implements Serializable {
	
	/** 
	 * The time frame within which each 'expression' must be true in order to
	 * trigger this rule.
	 */
	@ManyToOne(cascade = CascadeType.ALL)
	private Interval interval;
	
	/**
	 * The list of expressions that must resolve to true in order to
	 * trigger this rule
	 */
	//TODO: add proper annotation
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
