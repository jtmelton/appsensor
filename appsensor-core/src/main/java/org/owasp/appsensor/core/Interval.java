package org.owasp.appsensor.core;


import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * The Interval represents a span of time. The key components are the: 
 * 
 * <ul>
 * 		<li>duration (example: 15)</li>
 * 		<li>unit: (example: minutes)</li>
 * </ul>
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Entity
public class Interval implements IAppsensorEntity {

	/** Constant representing seconds unit of time */
	public static final String SECONDS = "seconds";
	
	/** Constant representing minutes unit of time */
	public static final String MINUTES = "minutes";
	
	/** Constant representing hours unit of time */
	public static final String HOURS = "hours";
	
	/** Constant representing days unit of time */
	public static final String DAYS = "days";
	
	private static final long serialVersionUID = 6660305744465650539L;

	@Id
	@Column(columnDefinition = "integer")
	@GeneratedValue
	private String id;
	
	/** 
	 * Duration portion of interval, ie. '3' if you wanted 
	 * to represent an interval of '3 minutes' 
	 */
	@Column
	private int duration;
	
	/** 
	 * Unit portion of interval, ie. 'minutes' if you wanted 
	 * to represent an interval of '3 minutes'.
	 * Constants are provided in the Interval class for the 
	 * units supported by the reference implementation, ie.
	 * SECONDS, MINUTES, HOURS, DAYS.
	 */
	@Column
	private String unit;

	public Interval() {}
	
	public Interval(int duration, String unit) {
		setDuration(duration);
		setUnit(unit);
	}
	
	public int getDuration() {
		return duration;
	}

	public Interval setDuration(int duration) {
		this.duration = duration;
		return this;
	}
	
	public String getUnit() {
		return unit;
	}

	@Override
	public String getId() {
		return id;
	}

	@Override
	public void setId(String id) {
		this.id = id;
	}

	public Interval setUnit(String unit) {
		this.unit = unit;
		return this;
	}
	
	public long toMillis() {
		long millis = 0;
		
		if (SECONDS.equals(getUnit())) {
			millis = 1000 * getDuration();
		} else if (MINUTES.equals(getUnit())) {
			millis = 1000 * 60 * getDuration();
		} else if (HOURS.equals(getUnit())) {
			millis = 1000 * 60 * 60 * getDuration();
		} else if (DAYS.equals(getUnit())) {
			millis = 1000 * 60 * 60 * 24 * getDuration();
		} 
		
		return millis;
	}
	
	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(duration).
				append(unit).
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
		
		Interval other = (Interval) obj;
		
		return new EqualsBuilder().
				append(duration, other.getDuration()).
				append(unit, other.getUnit()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
			       append("duration", duration).
			       append("unit", unit).
			       toString();
	}
	
}
