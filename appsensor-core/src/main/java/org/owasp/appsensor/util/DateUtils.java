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

	public static DateTime getCurrentTimestamp() {
		return new DateTime(DateTimeZone.UTC);
	}
	
	public static String getCurrentTimestampAsString() {
		return getCurrentTimestamp().toString();
	}
	
	public static DateTime fromString(String rfc3339Timestamp) {
		if (rfc3339Timestamp == null) {
			return null;
		}
		
		DateTime dateTime = new DateTime(rfc3339Timestamp, DateTimeZone.UTC);
		return dateTime;
	}
	
	public static DateTime epoch() {
		 MutableDateTime epoch = new MutableDateTime();
		 
	     epoch.setDate(0); 
	     epoch.setTime(0);
	        
	     return epoch.toDateTime();
	}
}
