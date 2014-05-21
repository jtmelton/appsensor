package org.owasp.appsensor;

import java.io.Serializable;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.appsensor.util.DateUtils;

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
public class Response implements Serializable {
	
	private static final long serialVersionUID = -4183973779552497656L;

	@Id
	@Column
	@GeneratedValue
	private Integer id;
	
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
	@Column
	private String detectionSystemId; 
	
	public Response() {}
	
	public Response (User user, String action, String detectionSystemId) {
		this(user, action, DateUtils.getCurrentTimestampAsString(), detectionSystemId, null);
	}
	
	public Response (User user, String action, String timestamp, String detectionSystemId) {
		this(user, action, timestamp, detectionSystemId, null);
	}
	
	public Response (User user, String action, String detectionSystemId, Interval interval) {
		this(user, action, DateUtils.getCurrentTimestampAsString(), detectionSystemId, interval);
	}
	
	public Response (User user, String action, String timestamp, String detectionSystemId, Interval interval) {
		setUser(user);
		setAction(action);
		setTimestamp(timestamp);
		setDetectionSystemId(detectionSystemId);
		setInterval(interval);
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

	public String getDetectionSystemId() {
		return detectionSystemId;
	}

	public Response setDetectionSystemId(String detectionSystemId) {
		this.detectionSystemId = detectionSystemId;
		return this;
	}
	
	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(user).
				append(timestamp).
				append(action).
				append(interval).
				append(detectionSystemId).
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
				append(detectionSystemId, other.getDetectionSystemId()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
			       append("user", user).
			       append("timestamp", timestamp).
			       append("action", action).
			       append("interval", interval).
			       append("detectionSystemId", detectionSystemId).
			       toString();
	}
	
}
