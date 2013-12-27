package org.owasp.appsensor;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;

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
public class DetectionPoint implements Serializable {
	
	private static final long serialVersionUID = -6294211676275622809L;

	/**
	 * Identifier for the detection point. (ex. "IE1", "RE2")
	 */
	private String id;
	
	/**
	 * Threshold for determining whether given detection point (associated event) 
	 * should be considered an attack.
	 */
	private Threshold threshold;
	
	/**
	 * Set of responses associated with given detection point.
	 */
	private Collection<Response> responses = new ArrayList<>();
	
	public DetectionPoint() {}
	
	public DetectionPoint(String id) {
		setId(id);
	}
	
	public DetectionPoint(String id, Threshold threshold) {
		setId(id);
		setThreshold(threshold);
	}
	
	public DetectionPoint(String id, Threshold threshold, Collection<Response> responses) {
		setId(id);
		setThreshold(threshold);
		setResponses(responses);
	}
	
	public String getId() {
		return id;
	}

	public DetectionPoint setId(String id) {
		this.id = id;
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
				append(id).
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
				append(id, other.getId()).
				append(threshold, other.getThreshold()).
				append(responses, other.getResponses()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
			       append("id", id).
			       append("threshold", threshold).
			       append("responses", responses).
			       toString();
	}

}
