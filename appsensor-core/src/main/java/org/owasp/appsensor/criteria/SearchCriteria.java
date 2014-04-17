package org.owasp.appsensor.criteria;

import java.util.Collection;

import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.User;

public class SearchCriteria {
	
	private User user;
	
	private DetectionPoint detectionPoint;
	
	private Collection<String> detectionSystemIds;
	
	private String earliest;
	
	public User getUser() {
		return user;
	}

	public SearchCriteria setUser(User user) {
		this.user = user;

		return this;
	}

	public DetectionPoint getDetectionPoint() {
		return detectionPoint;
	}

	public SearchCriteria setDetectionPoint(DetectionPoint detectionPoint) {
		this.detectionPoint = detectionPoint;

		return this;
	}

	public Collection<String> getDetectionSystemIds() {
		return detectionSystemIds;
	}

	public SearchCriteria setDetectionSystemIds(Collection<String> detectionSystemIds) {
		this.detectionSystemIds = detectionSystemIds;

		return this;
	}

	public String getEarliest() {
		return earliest;
	}

	public SearchCriteria setEarliest(String earliest) {
		this.earliest = earliest;
		
		return this;
	}

}
