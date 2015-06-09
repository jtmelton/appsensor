package org.owasp.appsensor.core;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.appsensor.core.util.DateUtils;

/**
 * Event is a specific instance that a sensor has detected that 
 * represents a suspicious activity.
 * 
 * The key difference between an {@link Event} and an {@link Attack} is that an {@link Event}
 * is "suspicous" whereas an {@link Attack} has been determined to be "malicious" by some analysis.
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Entity
public class Event implements Serializable {
	
	@Id
	@Column
	@GeneratedValue
	private Integer id;
	
	private static final long serialVersionUID = -3235111340901139594L;

	/** User who triggered the event, could be anonymous user */
	@ManyToOne(cascade = CascadeType.ALL)
	private User user;
	
	/** Detection Point that was triggered */
	@ManyToOne(cascade = CascadeType.ALL)
	private DetectionPoint detectionPoint;
	
	/** When the event occurred */
	@Column
	private String timestamp;

	/** 
	 * Identifier label for the system that detected the event. 
	 * This will be either the client application, or possibly an external 
	 * detection system, such as syslog, a WAF, network IDS, etc.  */
	@ManyToOne(cascade = CascadeType.ALL)
	private DetectionSystem detectionSystem;  
	
	/** 
	 * The resource being requested when the event was triggered, which can be used 
     * later to block requests to a given function. 
     */
	@ManyToOne(cascade = CascadeType.ALL)
    private Resource resource;
	
	/** Represent extra metadata, anything client wants to send */
	@ElementCollection
	private Collection<KeyValuePair> metadata = new ArrayList<>();
	
    public Event () {}
    
	public Event (User user, DetectionPoint detectionPoint, DetectionSystem detectionSystem) {
		this(user, detectionPoint, DateUtils.getCurrentTimestampAsString(), detectionSystem);
	}
	
	public Event (User user, DetectionPoint detectionPoint, String timestamp, DetectionSystem detectionSystem) {
		setUser(user);
		setDetectionPoint(detectionPoint);
		setTimestamp(timestamp);
		setDetectionSystem(detectionSystem);
	}
	
	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public User getUser() {
		return user;
	}

	public Event setUser(User user) {
		this.user = user;
		return this;
	}

	public DetectionPoint getDetectionPoint() {
		return detectionPoint;
	}

	public Event setDetectionPoint(DetectionPoint detectionPoint) {
		this.detectionPoint = detectionPoint;
		return this;
	}

	public String getTimestamp() {
		return timestamp;
	}

	public Event setTimestamp(String timestamp) {
		this.timestamp = timestamp;
		return this;
	}
	
	public DetectionSystem getDetectionSystem() {
		return detectionSystem;
	}

	public Event setDetectionSystem(DetectionSystem detectionSystem) {
		this.detectionSystem = detectionSystem;
		return this;
	}

	public Resource getResource() {
		return resource;
	}

	public Event setResource(Resource resource) {
		this.resource = resource;
		return this;
	}
	
	public Collection<KeyValuePair> getMetadata() {
		return metadata;
	}

	public void setMetadata(Collection<KeyValuePair> metadata) {
		this.metadata = metadata;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(user).
				append(detectionPoint).
				append(timestamp).
				append(detectionSystem).
				append(resource).
				append(metadata).
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
		
		Event other = (Event) obj;
		
		return new EqualsBuilder().
				append(user, other.getUser()).
				append(detectionPoint, other.getDetectionPoint()).
				append(timestamp, other.getTimestamp()).
				append(detectionSystem, other.getDetectionSystem()).
				append(resource, other.getResource()).
				append(metadata, other.getMetadata()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
				append("user", user).
				append("detectionPoint", detectionPoint).
				append("timestamp", timestamp).
				append("detectionSystem", detectionSystem).
				append("resource", resource).
				append("metadata", metadata).
			    toString();
	}
}
