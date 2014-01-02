package org.owasp.appsensor;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlSeeAlso;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.appsensor.event.StatisticalEvent;

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
@XmlSeeAlso({StatisticalEvent.class})
public abstract class Event implements Serializable {
	
	/** Event type representing policy-based statistical event, default event type for appsensor */
	public static final String STATISTICAL = "STATISTICAL";
	
	private static final long serialVersionUID = -3235111340901139594L;

	/** User who triggered the event, could be anonymous user */
	private User user;
	
	/** Detection Point that was triggered */
	private DetectionPoint detectionPoint;
	
	/** When the event occurred */
	private long timestamp;

	/** 
	 * Identifier label for the system that detected the event. 
	 * This will be either the client application, or possibly an external 
	 * detection system, such as syslog, a WAF, network IDS, etc.  */
	private String detectionSystemId; 
	
	/** 
	 * The resource being requested when the event was triggered, which can be used 
     * later to block requests to a given function. 
     */
    private Resource resource;
    
    /** The type of event: ie. statistical, behavioral, etc. */
	private String eventType;
	
	protected Event() {}
	
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

	public long getTimestamp() {
		return timestamp;
	}

	public Event setTimestamp(long timestamp) {
		this.timestamp = timestamp;
		return this;
	}
	
	public String getDetectionSystemId() {
		return detectionSystemId;
	}

	public Event setDetectionSystemId(String detectionSystemId) {
		this.detectionSystemId = detectionSystemId;
		return this;
	}

	public Resource getResource() {
		return resource;
	}

	public Event setResource(Resource resource) {
		this.resource = resource;
		return this;
	}
	
	public String getEventType() {
		return eventType;
	}
	
	public Event setEventType(String eventType) {
		this.eventType = eventType;
		return this;
	}
	
	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(user).
				append(detectionPoint).
				append(timestamp).
				append(detectionSystemId).
				append(resource).
				append(eventType).
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
				append(detectionSystemId, other.getDetectionSystemId()).
				append(resource, other.getResource()).
				append(eventType, other.getEventType()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
				append("user", user).
				append("detectionPoint", detectionPoint).
				append("timestamp", timestamp).
				append("detectionSystemId", detectionSystemId).
				append("resource", resource).
				append("eventType", eventType).
			    toString();
	}
}
