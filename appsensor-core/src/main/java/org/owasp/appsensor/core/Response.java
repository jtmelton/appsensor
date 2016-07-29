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
import org.joda.time.DateTime;
import org.owasp.appsensor.core.util.DateUtils;

/**
 * After an {@link Attack} has been determined to have occurred, a Response
 * is executed. The Response configuration is done on the server-side, not 
 * the client application. 
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Entity
public class Response implements IAppsensorEntity {
	
	private static final long serialVersionUID = -4183973779552497656L;

	@Id
	@Column(columnDefinition = "integer")
	@GeneratedValue
	private String id;
	
	/** User the response is for */
	@ManyToOne(cascade = CascadeType.ALL)
	private User user;
	
	/** When the event occurred */
	@Column
	private String timestamp;
	
	/** String representing response action name */
	@Column
	private String action;
	
	/** Interval response should last for, if applicable. Ie. block access for 30 minutes */
	@ManyToOne(cascade = CascadeType.ALL)
	private Interval interval;

	/** Client application name that response applies to. */
	@ManyToOne(cascade = CascadeType.ALL)
	private DetectionSystem detectionSystem;
	
	/** Represent extra metadata, anything client wants to send */
	@ElementCollection
	private Collection<KeyValuePair> metadata = new ArrayList<>();
	
	private boolean active = false;
	
	public Response() {}
	
	public Response (User user, String action, DetectionSystem detectionSystem) {
		this(user, action, DateUtils.getCurrentTimestampAsString(), detectionSystem, null);
	}
	
	public Response (User user, String action, String timestamp, DetectionSystem detectionSystem) {
		this(user, action, timestamp, detectionSystem, null);
	}
	
	public Response (User user, String action, DetectionSystem detectionSystem, Interval interval) {
		this(user, action, DateUtils.getCurrentTimestampAsString(), detectionSystem, interval);
	}
	
	public Response (User user, String action, String timestamp, DetectionSystem detectionSystem, Interval interval) {
		setUser(user);
		setAction(action);
		setTimestamp(timestamp);
		setDetectionSystem(detectionSystem);
		setInterval(interval);
	}
	
	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public User getUser() {
		return user;
	}

	public Response setUser(User user) {
		this.user = user;
		return this;
	}

	public String getTimestamp() {
		return timestamp;
	}

	public Response setTimestamp(String timestamp) {
		this.timestamp = timestamp;
		return this;
	}

	public String getAction() {
		return action;
	}

	public Response setAction(String action) {
		this.action = action;
		return this;
	}

	public Interval getInterval() {
		return interval;
	}

	public Response setInterval(Interval interval) {
		this.interval = interval;
		return this;
	}

	public DetectionSystem getDetectionSystem() {
		return detectionSystem;
	}

	public Response setDetectionSystem(DetectionSystem detectionSystem) {
		this.detectionSystem = detectionSystem;
		return this;
	}
	
	public Collection<KeyValuePair> getMetadata() {
		return metadata;
	}

	public void setMetadata(Collection<KeyValuePair> metadata) {
		this.metadata = metadata;
	}
	
	public boolean isActive() {
		
		// if there is no interval, the response is executed immediately and hence does not have active/inactive state
		if (interval == null) {
			return false;
		}
		
		boolean localActive = false;
		
		DateTime responseStartTime = DateUtils.fromString(getTimestamp());
		DateTime responseEndTime = responseStartTime.plus(interval.toMillis());
		
		DateTime now = DateUtils.getCurrentTimestamp();
		
		// only active if current time between response start and end time
		if (responseStartTime.isBefore(now) && responseEndTime.isAfter(now)) {
			localActive = true;
		}
		
		active = localActive;
		
		return active;
	}
	
	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(user).
				append(timestamp).
				append(action).
				append(interval).
				append(detectionSystem).
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
		
		Response other = (Response) obj;
		
		return new EqualsBuilder().
				append(user, other.getUser()).
				append(timestamp, other.getTimestamp()).
				append(action, other.getAction()).
				append(interval, other.getInterval()).
				append(detectionSystem, other.getDetectionSystem()).
				append(metadata, other.getMetadata()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
			       append("user", user).
			       append("timestamp", timestamp).
			       append("action", action).
			       append("interval", interval).
			       append("detectionSystem", detectionSystem).
			       append("metadata", metadata).
			       toString();
	}
	
}
