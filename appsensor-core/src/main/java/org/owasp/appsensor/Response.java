package org.owasp.appsensor;

import java.io.Serializable;
import java.sql.Date;
import java.sql.Timestamp;
import java.util.Calendar;

import javax.xml.bind.annotation.XmlTransient;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * After an {@link Attack} has been determined to have occurred, a Response
 * is executed. The Response configuration is done on the server-side, not 
 * the client application. 
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class Response implements Serializable {
	
	private static final long serialVersionUID = -4183973779552497656L;

	private User user;
	
	/** Detection Point that was triggered */
	
	private DetectionPoint detectionPoint;
	
	/** When the event occurred */
	private long timestamp;
	
	private String action;
	
	private Interval interval;

	private String detectionSystemId; 
	
	public Response() {}
	
	public Response (User user, String action, DetectionPoint detectionPoint, String detectionSystemId) {
		this(user, action, detectionPoint, Calendar.getInstance().getTimeInMillis(), detectionSystemId, null);
	}
	
	public Response (User user, String action, DetectionPoint detectionPoint, long timestamp, String detectionSystemId) {
		this(user, action, detectionPoint, timestamp, detectionSystemId, null);
	}
	
	public Response (User user, String action, DetectionPoint detectionPoint, Date timestamp, String detectionSystemId) {
		this(user, action, detectionPoint, timestamp.getTime(), detectionSystemId, null);
	}
	
	public Response (User user, String action, DetectionPoint detectionPoint, Timestamp timestamp, String detectionSystemId) {
		this(user, action, detectionPoint, timestamp.getTime(), detectionSystemId, null);
	}
	
	public Response (User user, String action, DetectionPoint detectionPoint, String detectionSystemId, Interval interval) {
		this(user, action, detectionPoint, Calendar.getInstance().getTimeInMillis(), detectionSystemId, interval);
	}
	
	public Response (User user, String action, DetectionPoint detectionPoint, long timestamp, String detectionSystemId, Interval interval) {
		setUser(user);
		setAction(action);
		setDetectionPoint(detectionPoint);
		setTimestamp(timestamp);
		setDetectionSystemId(detectionSystemId);
		setInterval(interval);
	}
	
	public Response (User user, String action, DetectionPoint detectionPoint, Date timestamp, String detectionSystemId, Interval interval) {
		this(user, action, detectionPoint, timestamp.getTime(), detectionSystemId, interval);
	}
	
	public Response (User user, String action, DetectionPoint detectionPoint, Timestamp timestamp, String detectionSystemId, Interval interval) {
		this(user, action, detectionPoint, timestamp.getTime(), detectionSystemId, interval);
	}
	
	public User getUser() {
		return user;
	}

	public Response setUser(User user) {
		this.user = user;
		return this;
	}
	
	@XmlTransient
	public DetectionPoint getDetectionPoint() {
		return detectionPoint;
	}

	public Response setDetectionPoint(DetectionPoint detectionPoint) {
		this.detectionPoint = detectionPoint;
		return this;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public Response setTimestamp(long timestamp) {
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
	
	
//	private String ; 	
	
	
	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(user).
				append(detectionPoint).
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
				append(detectionPoint, other.getDetectionPoint()).
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
			       append("detectionPoint", detectionPoint).
			       append("timestamp", timestamp).
			       append("action", action).
			       append("interval", interval).
			       append("detectionSystemId", detectionSystemId).
			       toString();
	}
	
}
