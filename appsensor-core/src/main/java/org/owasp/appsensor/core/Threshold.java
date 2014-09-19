package org.owasp.appsensor.core;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * The Threshold represents a number of occurrences over a span of time. The key components are the: 
 * 
 * <ul>
 * 		<li>count: (example: 12)</li>
 * 		<li>interval: (example: 15 minutes)</li>
 * </ul>
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Entity
public class Threshold implements Serializable {

	private static final long serialVersionUID = -9033433180585877243L;

	@Id
	@Column
	@GeneratedValue
	private Integer id;
	
	/** The count at which this threshold is triggered. */
	private int count = 0;
	
	/** 
	 * The time frame within which 'count' number of actions has to be detected in order to
	 * trigger this threshold.
	 */
	private Interval interval;

	public Threshold() {}
	
	public Threshold(int count, Interval interval) {
		setCount(count);
		setInterval(interval);
	}
	
	public int getCount() {
		return count;
	}

	public Threshold setCount(int count) {
		this.count = count;
		return this;
	}

	public Interval getInterval() {
		return interval;
	}

	public Threshold setInterval(Interval interval) {
		this.interval = interval;
		return this;
	}
	
	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(count).
				append(interval).
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
		
		Threshold other = (Threshold) obj;
		
		return new EqualsBuilder().
				append(count, other.getCount()).
				append(interval, other.getInterval()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
			       append("count", count).
			       append("interval", interval).
			       toString();
	}
	
}
