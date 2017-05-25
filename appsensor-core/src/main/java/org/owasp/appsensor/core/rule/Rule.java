package org.owasp.appsensor.core.rule;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;
import javax.xml.bind.annotation.XmlTransient;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.codehaus.jackson.annotate.JsonProperty;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.IAppsensorEntity;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.Response;

/**
 * A Rule defines a logical aggregation of {@link MonitorPoint}s to determine if an
 * {@link Attack} is occurring. A Rule uses the boolean operators "AND" and "OR" as well
 * as the temporal operator "THEN" in joining {@link MonitorPoint}s into a Rule.
 *
 * For example:
 * 		A rule could be as simple as: "MP1 AND MP2"
 * 		Where the Rule will generate an attack if both MonitorPoint 1 and 2
 * 		are violated within the Rule's window.
 *
 * 		More complex: "MP1 AND MP2 THEN MP3 OR MP4"
 *
 * 		Even more complex: "MP1 AND MP2 THEN MP3 OR MP4 THEN MP5 AND MP6 OR MP7"
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */
@Entity
public class Rule implements IAppsensorEntity {

	private static final long serialVersionUID = 4314918375146512865L;

	@Id
	@Column(columnDefinition = "integer")
	@GeneratedValue
	private String id;

	/**
	 * Unique identifier
	 */
	@Column
	private String guid;

	/** An optional human-friendly name for the Rule */
	@Column
	private String name;

	/**
	 * The window is the time all {@link Expression}s must be triggered within.
	 * A Rule's window must be greater than or equal to the total of it's Expressions' windows.
	 */
	@ManyToOne(cascade = CascadeType.ALL)
	@JsonProperty("window")
	private Interval window;

	/** The {@link Expression}s that build up a Rule
	 * 	The order of the list corresponds to the temporal order of the expressions.
	 */
	@Transient
	@JsonProperty("expressions")
	private ArrayList<Expression> expressions;

	/**
	 * Set of {@link Response}s associated with given Rule.
	 */
	@Transient
	@JsonProperty("responses")
	private Collection<Response> responses = new ArrayList<Response>();

	public Rule () {
		expressions = new ArrayList<Expression>();
		responses = new ArrayList<Response>();
	}

	public Rule (String guid, Interval window, ArrayList<Expression> expressions) {
		setGuid(guid);
		setWindow(window);
		setExpressions(expressions);
	}

	public Rule (String guid, Interval window, ArrayList<Expression> expressions, ArrayList<Response> responses) {
		setGuid(guid);
		setWindow(window);
		setExpressions(expressions);
		setResponses(responses);
	}

	public Rule (String guid, Interval window, ArrayList<Expression> expressions, ArrayList<Response> responses, String name) {
		setGuid(guid);
		setWindow(window);
		setExpressions(expressions);
		setResponses(responses);
		setName(name);
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getGuid() {
		return this.guid;
	}

	public Rule setGuid(String guid) {
		this.guid = guid;
		return this;
	}

	public String getName() {
		return this.name;
	}

	public Rule setName(String name) {
		this.name = name;
		return this;
	}

	@XmlTransient
	@JsonProperty("window")
	public Interval getWindow() {
		return this.window;
	}

	@JsonProperty("window")
	public Rule setWindow(Interval window) {
		this.window = window;
		return this;
	}

	@XmlTransient
	@JsonProperty("expressions")
	public ArrayList<Expression> getExpressions() {
		return this.expressions;
	}

	@JsonProperty("expressions")
	public Rule setExpressions(ArrayList<Expression> expression) {
		this.expressions = expression;
		return this;
	}

	@XmlTransient
	@JsonProperty("responses")
	public Collection<Response> getResponses() {
		return this.responses;
	}

	@JsonProperty("responses")
	public Rule setResponses(Collection<Response> responses) {
		this.responses = responses;
		return this;
	}

	/* returns the last expression in expressions */
	public Expression getLastExpression() {
		return this.expressions.get(this.expressions.size() - 1);
	}

	/* checks whether the last expression contains a DetectionPoint
	 * matching the type of triggerDetectionPoint */
	public boolean checkLastExpressionForDetectionPoint (DetectionPoint triggerDetectionPoint) {
		for (DetectionPoint detectionPoint : getLastExpression().getDetectionPoints()) {
			if (detectionPoint.typeMatches(triggerDetectionPoint)) {
				return true;
			}
		}

		return false;
	}

	/* returns all DetectionPoints contained within the Rule as a set*/
	public Collection<DetectionPoint> getAllDetectionPoints () {
		Set<DetectionPoint> detectionPoints = new HashSet<DetectionPoint>();

		for (Expression expression : this.expressions) {
			detectionPoints.addAll(expression.getDetectionPoints());
		}

		return detectionPoints;
	}

	/* checks whether the Rule contains a detection point of the same type and threshold
	 * as the detectionPoint parameter */
	public boolean typeAndThresholdContainsDetectionPoint(DetectionPoint detectionPoint) {
		for (DetectionPoint myPoint : getAllDetectionPoints()) {
			if (detectionPoint.typeAndThresholdMatches(myPoint)) {
				return true;
			}
		}
		return false;
	}

	/* checks whether other rule has same guid, i.e. is the same rule */
	public boolean guidMatches(Rule other) {
		if (other == null) {
			throw new IllegalArgumentException("other must be non-null");
		}

		boolean matches = true;

		matches &= (guid != null) ? guid.equals(other.getGuid()) : true;

		return matches;
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
				append(this.guid, other.getGuid()).
				isEquals();
	}

	@Override
	public String toString() {
		return new ToStringBuilder(this).
				   append("window", window).
			       append("expressions", expressions).
			       append("responses", responses).
			       append("guid", guid).
			       append("name", name).
			       toString();
	}
}