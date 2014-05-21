package org.owasp.appsensor;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Transient;
import javax.xml.bind.annotation.XmlTransient;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * The detection point represents the unique sensor concept in the code. 
 * 
 * A list of project detection points are maintained at {@link https://www.owasp.org/index.php/AppSensor_DetectionPoints}
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Entity
public class DetectionPoint implements Serializable {
	
	private static final long serialVersionUID = -6294211676275622809L;

	@Id
	@Column
	@GeneratedValue
	private Integer id;
	
	/**
	 * Identifier for the detection point. (ex. "IE1", "RE2")
	 */
	private String label;
	
	/**
	 * {@link Threshold} for determining whether given detection point (associated {@link Event}) 
	 * should be considered an {@link Attack}.
	 */
	private Threshold threshold;
	
	/**
	 * Set of {@link Response}s associated with given detection point.
	 */
	@Transient
	private Collection<Response> responses = new ArrayList<Response>();
	
	public DetectionPoint() {}
	
	public DetectionPoint(String label) {
		setLabel(label);
	}
	
	public DetectionPoint(String label, Threshold threshold) {
		setLabel(label);
		setThreshold(threshold);
	}
	
	public DetectionPoint(String label, Threshold threshold, Collection<Response> responses) {
		setLabel(label);
		setThreshold(threshold);
		setResponses(responses);
	}
	
	public String getLabel() {
		return label;
	}

	public DetectionPoint setLabel(String label) {
		this.label = label;
		return this;
	} 
	
	@XmlTransient
	public Threshold getThreshold() {
		return threshold;
	}

	public DetectionPoint setThreshold(Threshold threshold) {
		this.threshold = threshold;
		return this;
	}

	@XmlTransient
	public Collection<Response> getResponses() {
		return responses;
	}

	public DetectionPoint setResponses(Collection<Response> responses) {
		this.responses = responses;
		return this;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(label).
				append(threshold).
				append(responses).
				toHashCode();
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
				append(label, other.getLabel()).
				append(threshold, other.getThreshold()).
				append(responses, other.getResponses()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
			       append("label", label).
			       append("threshold", threshold).
			       append("responses", responses).
			       toString();
	}

}
