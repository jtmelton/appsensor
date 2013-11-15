package org.owasp.appsensor;

import java.io.Serializable;
import java.util.Collection;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

public class DetectionPoint implements Serializable {
	
	private static final long serialVersionUID = -6294211676275622809L;

	private String id;
	
	private Threshold threshold;
	
	@XmlElementWrapper(name="responses")
	@XmlElement(name="response")
	private Collection<Response> responses;
	
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

	public void setId(String id) {
		this.id = id;
	} 
	
	public Threshold getThreshold() {
		return threshold;
	}

	public void setThreshold(Threshold threshold) {
		this.threshold = threshold;
	}

	public Collection<Response> getResponses() {
		return responses;
	}

	public void setResponses(Collection<Response> responses) {
		this.responses = responses;
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
