package org.owasp.appsensor.core;

import org.junit.Assert;
import org.junit.Test;

public class DetectionPointTest {

	@Test(expected=IllegalArgumentException.class)
	public void testTypeMatchesNull() {
		DetectionPoint point1 = new DetectionPoint();
		point1.typeMatches(null);
	}
	
	@Test
	public void testTypeMatchesEmptyDetectionPoints() {
		DetectionPoint point1 = new DetectionPoint();
		DetectionPoint point2 = new DetectionPoint();
		
		Assert.assertTrue(point1.typeMatches(point2));
	}
	
	@Test
	public void testTypeMatchesFullMismatch() {
		DetectionPoint point1 = new DetectionPoint("a", "a1", 
				new Threshold(5, new Interval(1, Interval.SECONDS)));
		DetectionPoint point2 = new DetectionPoint("b", "b1", 
				new Threshold(5, new Interval(2, Interval.SECONDS)));
		
		Assert.assertFalse(point1.typeMatches(point2));
	}
	
	@Test
	public void testTypeMatchesCategoryMismatch() {
		DetectionPoint point1 = new DetectionPoint("a", "a1", 
				new Threshold(5, new Interval(1, Interval.SECONDS)));
		DetectionPoint point2 = new DetectionPoint("a", "b1", 
				new Threshold(5, new Interval(2, Interval.SECONDS)));
		
		Assert.assertFalse(point1.typeMatches(point2));
	}
	
	@Test
	public void testTypeMatchesLabelMismatch() {
		DetectionPoint point1 = new DetectionPoint("a", "a1", 
				new Threshold(5, new Interval(1, Interval.SECONDS)));
		DetectionPoint point2 = new DetectionPoint("b", "a1", 
				new Threshold(5, new Interval(2, Interval.SECONDS)));
		
		Assert.assertFalse(point1.typeMatches(point2));
	}
	
	@Test
	public void testTypeMatchesThresholdMismatch() {
		DetectionPoint point1 = new DetectionPoint("a", "a1", 
				new Threshold(5, new Interval(1, Interval.SECONDS)));
		DetectionPoint point2 = new DetectionPoint("a", "a1", 
				new Threshold(5, new Interval(2, Interval.SECONDS)));
		
		Assert.assertTrue(point1.typeMatches(point2));
	}
	
	@Test
	public void testTypeMatchesThresholdMatch() {
		DetectionPoint point1 = new DetectionPoint("a", "a1", 
				new Threshold(5, new Interval(1, Interval.SECONDS)));
		DetectionPoint point2 = new DetectionPoint("a", "a1", 
				new Threshold(5, new Interval(1, Interval.SECONDS)));
		
		Assert.assertTrue(point1.typeMatches(point2));
	}
	
	
	
	
//	public boolean typeMatches(DetectionPoint other) {
//		if (other == null) {
//			throw new IllegalArgumentException("other must be non-null");
//		}
//		
//		boolean matches = true;
//		
//		matches &= (category != null) ? category.equals(other.getCategory()) : true;
//		matches &= (label != null) ? label.equals(other.getLabel()) : true;
//		
//		return matches;
//	}
}
