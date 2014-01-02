package org.owasp.appsensor.event;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;

import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.User;

/**
 * Event representing a standard statistical event. This is an event 
 * that is intended to be processed by a statistical analysis engine.
 * <p> 
 * This is the type of engine provided by the reference analysis engine. 
 * It typically follows the simple policy construct of: 
 * </p>
 * <code>
 * 		Attack = X Events of a given detection point time in Y time by a given user
 * </code>
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class StatisticalEvent extends Event {

	private static final long serialVersionUID = 6616678807196478038L;

    public StatisticalEvent () {}
    
	public StatisticalEvent (User user, DetectionPoint detectionPoint, String detectionSystemId) {
		this(user, detectionPoint, Calendar.getInstance().getTimeInMillis(), detectionSystemId);
	}
	
	public StatisticalEvent (User user, DetectionPoint detectionPoint, long timestamp, String detectionSystemId) {
		setUser(user);
		setDetectionPoint(detectionPoint);
		setTimestamp(timestamp);
		setDetectionSystemId(detectionSystemId);
		setEventType(STATISTICAL);
	}
	
	public StatisticalEvent (User user, DetectionPoint detectionPoint, Date timestamp, String detectionSystemId) {
		this(user, detectionPoint, timestamp.getTime(), detectionSystemId);
	}
	
	public StatisticalEvent (User user, DetectionPoint detectionPoint, Timestamp timestamp, String detectionSystemId) {
		this(user, detectionPoint, timestamp.getTime(), detectionSystemId);
	}
	
}
