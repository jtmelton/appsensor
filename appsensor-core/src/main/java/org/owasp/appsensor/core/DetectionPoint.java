package org.owasp.appsensor.core;

import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.Transient;
import javax.xml.bind.annotation.XmlTransient;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The detection point represents the unique sensor concept in the code.
 *
 * A list of project detection points are maintained at https://www.owasp.org/index.php/AppSensor_DetectionPoints
 *
 * @see java.io.Serializable
 * @see <a href="https://www.owasp.org/index.php/AppSensor_DetectionPoints">https://www.owasp.org/index.php/AppSensor_DetectionPoints</a>
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Entity
public class DetectionPoint implements IAppsensorEntity {

	private static final long serialVersionUID = -6294211676275622809L;

	@Id
	@Column(columnDefinition = "integer")
	@GeneratedValue
	private String id;

	@Column
	private String guid;

	public class Category {
		public static final String REQUEST 				= "Request";
		public static final String AUTHENTICATION 		= "Authentication";
		public static final String SESSION_MANAGEMENT 	= "Session Management";
		public static final String ACCESS_CONTROL 		= "Access Control";
		public static final String INPUT_VALIDATION 	= "Input Validation";
		public static final String OUTPUT_ENCODING 		= "Output Encoding";
		public static final String COMMAND_INJECTION 	= "Command Injection";
		public static final String FILE_IO 				= "File IO";
		public static final String HONEY_TRAP 			= "Honey Trap";
		public static final String USER_TREND 			= "User Trend";
		public static final String SYSTEM_TREND 		= "System Trend";
		public static final String REPUTATION 			= "Reputation";
	}

	/**
	 * Category identifier for the detection point. (ex. "Request", "AccessControl", "SessionManagement")
	 */
	@Column
	private String category;

	/**
	 * Identifier for the detection point. (ex. "IE1", "RE2")
	 */
	@Column
	private String label;

	/**
	 * {@link Threshold} for determining whether given detection point (associated {@link Event})
	 * should be considered an {@link Attack}.
	 */
	@ManyToOne(cascade = CascadeType.ALL)
	@JsonProperty("threshold")
	private Threshold threshold;

	/**
	 * Set of {@link Response}s associated with given detection point.
	 */
	@Transient
	@JsonProperty("responses")
	private Collection<Response> responses = new ArrayList<Response>();

	public DetectionPoint() {}

	public DetectionPoint(String category, String label) {
		setCategory(category);
		setLabel(label);
	}

	public DetectionPoint(String category, String label, Threshold threshold) {
		setCategory(category);
		setLabel(label);
		setThreshold(threshold);
	}

	public DetectionPoint(String category, String label, Threshold threshold, Collection<Response> responses) {
		setCategory(category);
		setLabel(label);
		setThreshold(threshold);
		setResponses(responses);
	}

	public DetectionPoint(String category, String label, Threshold threshold, Collection<Response> responses, String guid) {
		setCategory(category);
		setLabel(label);
		setThreshold(threshold);
		setResponses(responses);
		setGuid(guid);
	}

	public String getCategory() {
		return category;
	}

	public DetectionPoint setCategory(String category) {
		this.category = category;
		return this;
	}

	public String getLabel() {
		return label;
	}

	public DetectionPoint setLabel(String label) {
		this.label = label;
		return this;
	}

	public String getGuid() {
		return guid;
	}

	public void setGuid(String guid) {
		this.guid = guid;
	}

	@Override
	public String getId() {
		return id;
	}

	@Override
	public void setId(String id) {
		this.id = id;
	}

	@XmlTransient
	@JsonProperty("threshold")
	public Threshold getThreshold() {
		return threshold;
	}

	@JsonProperty("threshold")
	public DetectionPoint setThreshold(Threshold threshold) {
		this.threshold = threshold;
		return this;
	}

	@XmlTransient
	@JsonProperty("responses")
	public Collection<Response> getResponses() {
		return responses;
	}

	@JsonProperty("responses")
	public DetectionPoint setResponses(Collection<Response> responses) {
		this.responses = responses;
		return this;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(category).
				append(label).
				append(threshold).
				append(responses).
				toHashCode();
	}

	public boolean typeMatches(DetectionPoint other) {
		if (other == null) {
			throw new IllegalArgumentException("other must be non-null");
		}

		boolean matches = true;

		matches &= (category != null) ? category.equals(other.getCategory()) : true;
		matches &= (label != null) ? label.equals(other.getLabel()) : true;

		return matches;
	}

	public boolean typeAndThresholdMatches(DetectionPoint other) {
		if (other == null) {
			throw new IllegalArgumentException("other must be non-null");
		}

		boolean matches = true;

		matches &= (category != null) ? category.equals(other.getCategory()) : true;
		matches &= (label != null) ? label.equals(other.getLabel()) : true;
		matches &= (threshold != null) ? threshold.equals(other.getThreshold()) : true;

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

		DetectionPoint other = (DetectionPoint) obj;

		return new EqualsBuilder().
				append(category, other.getCategory()).
				append(label, other.getLabel()).
				append(threshold, other.getThreshold()).
				append(responses, other.getResponses()).
				append(guid, other.getGuid()).
				isEquals();
	}

	@Override
	public String toString() {
		return new ToStringBuilder(this).
				   append("category", category).
			       append("label", label).
			       append("threshold", threshold).
			       append("responses", responses).
			       append("guid", guid).
			       toString();
	}

}
