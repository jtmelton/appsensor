package org.owasp.appsensor.ui.utils;

import java.util.Comparator;
import java.util.Map;
import java.util.TreeMap;

import org.owasp.appsensor.core.DetectionPoint;

public class Maps {
	
	public static TreeMap<String, Long> sortStringsByValue(Map<String, Long> unsorted) {
		StringComparator comparator =  new StringComparator(unsorted);
		TreeMap<String,Long> sortedMap = new TreeMap<>(comparator);
		sortedMap.putAll(unsorted);
		return sortedMap;
	}
	
	public static TreeMap<DetectionPoint, Long> sortDetectionPointsByValue(Map<DetectionPoint, Long> unsorted) {
		DetectionPointComparator comparator =  new DetectionPointComparator(unsorted);
		TreeMap<DetectionPoint,Long> sortedMap = new TreeMap<>(comparator);
		sortedMap.putAll(unsorted);
		return sortedMap;
	}

	static class StringComparator implements Comparator<String> {
		 
	    Map<String, Long> map;
	 
	    public StringComparator(Map<String, Long> base) {
	        this.map = base;
	    }
	 
	    public int compare(String a, String b) {
	        if (map.get(a) >= map.get(b)) {
	            return -1;
	        } else {
	            return 1;
	        } // returning 0 would merge keys 
	    }
	}
	
	static class DetectionPointComparator implements Comparator<DetectionPoint> {
		 
	    Map<DetectionPoint, Long> map;
	 
	    public DetectionPointComparator(Map<DetectionPoint, Long> base) {
	        this.map = base;
	    }
	 
	    public int compare(DetectionPoint a, DetectionPoint b) {
	        if (map.get(a) >= map.get(b)) {
	            return -1;
	        } else {
	            return 1;
	        } // returning 0 would merge keys 
	    }
	}
	
}
