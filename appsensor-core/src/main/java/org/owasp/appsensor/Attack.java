package org.owasp.appsensor;

import java.io.Serializable;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class Attack implements Serializable {

	private static final long serialVersionUID = 7231666413877649836L;

	/** User who triggered the attack, could be anonymous user */
	private User user;
	
	/** Detection Point that was triggered */
	private DetectionPoint detectionPoint;
	
	/** When the attack occurred */
	private long timestamp;

	/** Identifier label for the system that detected the attack. 
	 * This will be either the client application, or possible an external 
	 * detection system, such as syslog, a WAF, network IDS, etc.  */
	private String detectionSystemId; 
	
	/** The application specific location of the occurrence, which can be used 
     * later to block requests to a given function.  In this implementation, 
     * the current request URI is used.
     */
    private String resource;
	
	public Attack (User user, DetectionPoint detectionPoint, String detectionSystemId) {
		this(user, detectionPoint, Calendar.getInstance().getTimeInMillis(), detectionSystemId);
	}
	
	public Attack (User user, DetectionPoint detectionPoint, long timestamp, String detectionSystemId) {
		setUser(user);
		setDetectionPoint(detectionPoint);
		setTimestamp(timestamp);
		setDetectionSystemId(detectionSystemId);
	}
	
	public Attack (User user, DetectionPoint detectionPoint, Date timestamp, String detectionSystemId) {
		this(user, detectionPoint, timestamp.getTime(), detectionSystemId);
	}
	
	public Attack (User user, DetectionPoint detectionPoint, Timestamp timestamp, String detectionSystemId) {
		this(user, detectionPoint, timestamp.getTime(), detectionSystemId);
	}
	
	public Attack (Event event) {
		setUser(event.getUser());
		setDetectionPoint(event.getDetectionPoint());
		setTimestamp(event.getTimestamp());
		setDetectionSystemId(event.getDetectionSystemId());
		setResource(event.getResource());
	}
	
	public User getUser() {
		return user;
	}

	public Attack setUser(User user) {
		this.user = user;
		return this;
	}
	
	public DetectionPoint getDetectionPoint() {
		return detectionPoint;
	}

	public Attack setDetectionPoint(DetectionPoint detectionPoint) {
		this.detectionPoint = detectionPoint;
		return this;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public Attack setTimestamp(long timestamp) {
		this.timestamp = timestamp;
		return this;
	}
	
	public String getDetectionSystemId() {
		return detectionSystemId;
	}

	public Attack setDetectionSystemId(String detectionSystemId) {
		this.detectionSystemId = detectionSystemId;
		return this;
	}

	public String getResource() {
		return resource;
	}

	public Attack setResource(String resource) {
		this.resource = resource;
		return this;
	}

}
