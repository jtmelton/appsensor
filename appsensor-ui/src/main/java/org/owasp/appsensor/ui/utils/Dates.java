package org.owasp.appsensor.ui.utils;

import java.util.LinkedList;
import java.util.List;

import org.joda.time.DateTime;
import org.joda.time.Interval;

public class Dates {

	public static List<Interval> splitRange(final DateTime from, final DateTime to, int slices) {
		List<Interval> ranges = new LinkedList<Interval>();
		
		long millisDifference = to.getMillis() - from.getMillis();
		
		long rangeInMillis = millisDifference / slices;
		
		for(int i = 0; i < slices; i++) {
			long startMillis = from.getMillis();
			
			if (ranges.size() > 0) {
				// add 1 ms to end time of previous range
				startMillis = ranges.get(i - 1).getEndMillis() + 1;
			}
			
			Interval range = new Interval(startMillis, startMillis + rangeInMillis);
			ranges.add(range);
		}
		
		return ranges;
	}
	
}
