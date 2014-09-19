package org.owasp.appsensor.core.correlation;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * The CorrelationSet represents a set of {@link ClientApplication}s that 
 * should be considered to share the same {@link User} base. 
 * 
 * For example if server1 and server2 are part of a correlation set, 
 * then client1/userA is considered the same {@link User} as client2/userA. 
 * 
 * This can be useful for simple tracking of {@link User} activity across multiple
 * {@link ClientApplication}s.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class CorrelationSet {

	/** {@link ClientApplication}s that are represented in this correlation set */
	private Collection<String> clientApplications = new ArrayList<>();
	
	public Collection<String> getClientApplications() {
		return clientApplications;
	}

	public CorrelationSet setClientApplications(Collection<String> clientApplications) {
		this.clientApplications = clientApplications;
		return this;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(clientApplications).
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
		
		CorrelationSet other = (CorrelationSet) obj;
		
		return new EqualsBuilder().
				append(clientApplications, other.getClientApplications()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
			       append("clientApplications", clientApplications).
			       toString();
	}

}
