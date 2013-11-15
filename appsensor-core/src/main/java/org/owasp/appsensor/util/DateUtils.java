package org.owasp.appsensor.util;

import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

public class DateUtils {

	public static long getCurrentTime() {
		TimeZone tz = TimeZone.getDefault();
		Calendar cal = Calendar.getInstance(tz);
		Date date = cal.getTime();
		long currentTime = date.getTime();
		return currentTime;
	}
	
}
