package org.owasp.appsensor.util;

import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * Helper class for Date related utility methods
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class DateUtils {

	public static long getCurrentTime() {
		TimeZone tz = TimeZone.getDefault();
		Calendar cal = Calendar.getInstance(tz);
		Date date = cal.getTime();
		long currentTime = date.getTime();
		return currentTime;
	}
	
}
