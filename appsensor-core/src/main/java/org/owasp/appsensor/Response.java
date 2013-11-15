package org.owasp.appsensor;

import java.io.Serializable;
import java.sql.Date;
import java.sql.Timestamp;
import java.util.Calendar;

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

	public void setUser(User user) {
		this.user = user;
	}
	
	public DetectionPoint getDetectionPoint() {
		return detectionPoint;
	}

	public void setDetectionPoint(DetectionPoint detectionPoint) {
		this.detectionPoint = detectionPoint;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	public String getAction() {
		return action;
	}

	public void setAction(String action) {
		this.action = action;
	}

	public Interval getInterval() {
		return interval;
	}

	public void setInterval(Interval interval) {
		this.interval = interval;
	}

	public String getDetectionSystemId() {
		return detectionSystemId;
	}

	public void setDetectionSystemId(String detectionSystemId) {
		this.detectionSystemId = detectionSystemId;
	}
	
}
