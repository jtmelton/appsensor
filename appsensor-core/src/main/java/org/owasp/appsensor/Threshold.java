package org.owasp.appsensor;

import java.io.Serializable;

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
public class Threshold implements Serializable {

	private static final long serialVersionUID = -9033433180585877243L;

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
	
}
