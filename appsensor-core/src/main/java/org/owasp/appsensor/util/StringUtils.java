package org.owasp.appsensor.util;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Helper class for String related utility methods
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class StringUtils {
	
	/** Empty String */
	public static final String EMPTY = "";
	
	public static Collection<String> toCollection(String value) {
		Collection<String> collection = new ArrayList<String>();
		
		collection.add(value);
		
		return collection;
	}
	
}
