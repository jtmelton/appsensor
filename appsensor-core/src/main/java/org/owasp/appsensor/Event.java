package org.owasp.appsensor;

import java.io.Serializable;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class Event implements Serializable {
	
	private static final long serialVersionUID = -3235111340901139594L;

	/** User who triggered the event, could be anonymous user */
	private User user;
	
	/** Detection Point that was triggered */
	private DetectionPoint detectionPoint;
	
	/** When the event occurred */
	private long timestamp;

	/** Identifier label for the system that detected the event. 
	 * This will be either the client application, or possible an external 
	 * detection system, such as syslog, a WAF, network IDS, etc.  */
	private String detectionSystemId; 
	
	/** The application specific location of the occurrence, which can be used 
     * later to block requests to a given function.  In this implementation, 
     * the current request URI is used.
     */
    private String resource;
	
    public Event () {}
    
	public Event (User user, DetectionPoint detectionPoint, String detectionSystemId) {
		this(user, detectionPoint, Calendar.getInstance().getTimeInMillis(), detectionSystemId);
	}
	
	public Event (User user, DetectionPoint detectionPoint, long timestamp, String detectionSystemId) {
		setUser(user);
		setDetectionPoint(detectionPoint);
		setTimestamp(timestamp);
		setDetectionSystemId(detectionSystemId);
	}
	
	public Event (User user, DetectionPoint detectionPoint, Date timestamp, String detectionSystemId) {
		this(user, detectionPoint, timestamp.getTime(), detectionSystemId);
	}
	
	public Event (User user, DetectionPoint detectionPoint, Timestamp timestamp, String detectionSystemId) {
		this(user, detectionPoint, timestamp.getTime(), detectionSystemId);
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

	public String getResource() {
		return resource;
	}

	public Event setResource(String resource) {
		this.resource = resource;
		return this;
	}
	
}
