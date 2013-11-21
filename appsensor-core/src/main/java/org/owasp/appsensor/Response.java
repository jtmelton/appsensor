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

	public Response setUser(User user) {
		this.user = user;
		return this;
	}
	
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
	
}
