package org.owasp.appsensor.ui.controller;

import java.util.ArrayList;
import java.util.Collection;

import org.joda.time.DateTime;
import org.owasp.appsensor.core.util.DateUtils;
import org.owasp.appsensor.ui.rest.RestReportingEngineFacade;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class TrendsDashboardController {

	@Autowired
	RestReportingEngineFacade facade;
	
	@RequestMapping(value="/trends-dashboard", method = RequestMethod.GET)
	public String home() {
		return "trends-dashboard";
	}

	@RequestMapping(value="/api/trends/by-time-frame", method = RequestMethod.GET)
	@ResponseBody
	public Collection<TrendItem> countEvents() {
		Collection<TrendItem> trends = new ArrayList<>();
		
		DateTime now = DateUtils.getCurrentTimestamp();
		DateTime monthAgo = now.minusMonths(1);
		DateTime weekAgo = now.minusWeeks(1);
		DateTime dayAgo = now.minusDays(1);
		DateTime shiftAgo = now.minusHours(8);
		DateTime hourAgo = now.minusHours(1);
		
		int monthAgoEventCount = facade.countEvents(monthAgo.toString());
		int weekAgoEventCount = facade.countEvents(weekAgo.toString());
		int dayAgoEventCount = facade.countEvents(dayAgo.toString());
		int shiftAgoEventCount = facade.countEvents(shiftAgo.toString());
		int hourAgoEventCount = facade.countEvents(hourAgo.toString()); 
		
		int monthAgoResponseCount = facade.countResponses(monthAgo.toString());
		int weekAgoResponseCount = facade.countResponses(weekAgo.toString());
		int dayAgoResponseCount = facade.countResponses(dayAgo.toString());
		int shiftAgoResponseCount = facade.countResponses(shiftAgo.toString());
		int hourAgoResponseCount = facade.countResponses(hourAgo.toString());
		
		trends.add(TrendItem.of(monthAgoEventCount, TrendItem.TimeUnit.MONTH, TrendItem.Type.EVENT));
		trends.add(TrendItem.of(monthAgoResponseCount, TrendItem.TimeUnit.MONTH, TrendItem.Type.RESPONSE));
		trends.add(TrendItem.compute(weekAgoEventCount,  TrendItem.TimeUnit.WEEK, 
									 monthAgoEventCount, TrendItem.TimeUnit.MONTH, TrendItem.Type.EVENT));
		trends.add(TrendItem.compute(weekAgoResponseCount,  TrendItem.TimeUnit.WEEK, 
				 					 monthAgoResponseCount, TrendItem.TimeUnit.MONTH, TrendItem.Type.RESPONSE));
		trends.add(TrendItem.compute(dayAgoEventCount,   TrendItem.TimeUnit.DAY, 
				 					 monthAgoEventCount, TrendItem.TimeUnit.MONTH, TrendItem.Type.EVENT));
		trends.add(TrendItem.compute(dayAgoResponseCount,   TrendItem.TimeUnit.DAY, 
									 monthAgoResponseCount, TrendItem.TimeUnit.MONTH, TrendItem.Type.RESPONSE));
		trends.add(TrendItem.compute(shiftAgoEventCount, TrendItem.TimeUnit.SHIFT, 
									 monthAgoEventCount, TrendItem.TimeUnit.MONTH, TrendItem.Type.EVENT));
		trends.add(TrendItem.compute(shiftAgoResponseCount, TrendItem.TimeUnit.SHIFT, 
				 				 	 monthAgoResponseCount, TrendItem.TimeUnit.MONTH, TrendItem.Type.RESPONSE));
		trends.add(TrendItem.compute(hourAgoEventCount,  TrendItem.TimeUnit.HOUR, 
						 			 monthAgoEventCount, TrendItem.TimeUnit.MONTH, TrendItem.Type.EVENT));
		trends.add(TrendItem.compute(hourAgoResponseCount,  TrendItem.TimeUnit.HOUR, 
									 monthAgoResponseCount, TrendItem.TimeUnit.MONTH, TrendItem.Type.RESPONSE));

		return trends;
	}
	
	static class TrendItem {
		
		private static double DEFAULT_TREND_DELTA_PERCENTAGE = 20.0;
		
		private enum TrendDirection {
			HIGHER, LOWER, SAME;
		
			public static TrendDirection of(int base, int variation) {
				TrendDirection direction = SAME;
				
				if (base == variation) {
					direction = SAME;
				} else if (base > variation && variation == 0) {
					direction = LOWER;
				} else if (base < variation && base == 0) {
					direction = HIGHER;
				} else {
					
					// actually calculate difference %
					double baseDbl = Double.valueOf(base);
					double variationDbl = Double.valueOf(variation);
					double difference = baseDbl - variationDbl;
					double percentageDifference = Math.abs(difference / variationDbl) * 100.0;
					
					if (percentageDifference < DEFAULT_TREND_DELTA_PERCENTAGE) {
						direction = SAME;
					} else if (base > variation) {
						direction = LOWER;
					} else if (base < variation) {
						direction = HIGHER;
					}
				}
				
				return direction;
			}
			
		}
		
		private enum TimeUnit { 
			
			MONTH, WEEK, DAY, SHIFT, HOUR;
			
			public int toHours() {
				int hours = 0;
				
				switch (this) {
				case MONTH:
					hours = 30 * 24;
					break;
				case WEEK:
					hours = 7 * 24;
					break;
				case DAY:
					hours = 24;
					break;
				case SHIFT:
					hours = 8;
					break;
				case HOUR:
					hours = 1;
					break;
				}
				
				return hours;
			}
		} 
		
		private enum Type { EVENT, RESPONSE } 
		
		private TrendDirection direction; 
		private TimeUnit unit;
		private int count;
		private Type type;
		
		public static TrendItem of(int countOverTimeUnit, TimeUnit unit, Type type) {
			return new TrendItem(countPerHour(countOverTimeUnit, unit), TrendDirection.SAME, unit, type);
		}
		
		// denominator is always a month, so this would be events/responses in a day compared to a month 
		public static TrendItem compute(int countVariation, TimeUnit unitVariation, 
				   					    int countBase, 		TimeUnit unitBase, Type type) {
			
			int countVariationPerHour = countPerHour(countVariation, unitVariation);
			int countBasePerHour = countPerHour(countBase, unitBase);
			
			return new TrendItem(countVariationPerHour, TrendDirection.of(countBasePerHour, countVariationPerHour), unitVariation, type);
		}
		
		private static int countPerHour(int count, TimeUnit unit) {
			int perHour = 0;
			
			if (count > 0) {
				perHour = count / unit.toHours();
			}
			
			return perHour;
		}
		
		private TrendItem(int count,TrendDirection direction, TimeUnit unit, Type type) {
			this.count = count;
			this.direction = direction;
			this.unit = unit;
			this.type = type;
		}

		public TrendDirection getDirection() {
			return direction;
		}

		public TimeUnit getUnit() {
			return unit;
		}

		public int getCount() {
			return count;
		}
		
		public Type getType() {
			return type;
		}
		
	}
	
}
