package org.owasp.appsensor.core.criteria;

import java.util.Collection;

import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.util.DateUtils;

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
		return setEarliest(earliest, true);
	}

	public SearchCriteria setEarliest(String earliest, boolean inclusive) {
		if(inclusive) {
			this.earliest = earliest;
		} else {
			DateTime time = DateUtils.fromString(earliest);

			this.earliest = time
					.plus(Duration.standardSeconds(1))	// add one second if exclusive
					.toString();
		}

		return this;
	}

}
