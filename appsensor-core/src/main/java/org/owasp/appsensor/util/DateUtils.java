package org.owasp.appsensor.util;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.MutableDateTime;

/**
 * Helper class for Date/time related utility methods
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class DateUtils {

	/** 
	 * Helper for returning current timestamp in UTC zone
	 * @return current timestamp
	 */
	public static DateTime getCurrentTimestamp() {
		return new DateTime(DateTimeZone.UTC);
	}
	
	/** 
	 * Helper for returning current timestamp in UTC zone as a string
	 * @return current timestamp as string
	 */
	public static String getCurrentTimestampAsString() {
		return getCurrentTimestamp().toString();
	}
	
	/** 
	 * Helper for parsing rfc3339 compliant timestamp from string 
	 * 
	 * @param rfc3339Timestamp timestamp as string in rfc3339 format
	 * @return {@link DateTime} representing rfc3339 compliant timestamp from parameter
	 */
	public static DateTime fromString(String rfc3339Timestamp) {
		if (rfc3339Timestamp == null) {
			return null;
		}
		
		DateTime dateTime = new DateTime(rfc3339Timestamp, DateTimeZone.UTC);
		return dateTime;
	}
	
	/** 
	 * Helper for getting epoch {@link DateTime} object
	 * 
	 * @return {@link DateTime} representing epoch
	 */
	public static DateTime epoch() {
		 MutableDateTime epoch = new MutableDateTime();
		 
	     epoch.setDate(0); 
	     epoch.setTime(0);
	        
	     return epoch.toDateTime();
	}
}
