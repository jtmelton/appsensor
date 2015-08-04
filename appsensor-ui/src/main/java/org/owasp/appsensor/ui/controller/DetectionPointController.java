package org.owasp.appsensor.ui.controller;

import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.joda.time.DateTime;
import org.joda.time.Interval;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.util.DateUtils;
import org.owasp.appsensor.ui.rest.RestReportingEngineFacade;
import org.owasp.appsensor.ui.utils.Dates;
import org.owasp.appsensor.ui.utils.Maps;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;
import com.google.gson.Gson;

@Controller
public class DetectionPointController {

	@Autowired
	private RestReportingEngineFacade facade;

	private final Gson gson = new Gson();
	
	private final static String MORRIS_ID = "a1";
	
	private static final String DATE_FORMAT_STR = "YYYY-MM-dd HH:mm:ss";
	
	@RequestMapping(value="/api/detection-points/{label}/all", method = RequestMethod.GET)
	@ResponseBody
	public Map<String,Object> allContent(@PathVariable String label, @RequestParam("earliest") String rfc3339Timestamp, @RequestParam Long limit) { 
		Map<String,Object> allContent = new HashMap<>();
		
		allContent.put("detectionPointConfiguration", gson.toJson(facade.getConfiguredDetectionPoints(label)));
		
//		allContent.put("byTimeFrame", byTimeFrame());
//		allContent.put("byCategory", byCategory(rfc3339Timestamp));
//		allContent.put("groupedEvents", groupedEvents(rfc3339Timestamp, slices));
//		allContent.put("topUsers", userController.topUsers(rfc3339Timestamp, limit));
//		allContent.put("topDetectionPoints", detectionPointController.topDetectionPoints(rfc3339Timestamp, limit));
//		
		return allContent;
	}
	
	
	// seen by these client apps
	@RequestMapping(value="/api/detection-points/{label}/by-client-application", method = RequestMethod.GET)
	@ResponseBody
	public Table<String,TimeFrameItem.Type,Integer> byClientApplication(@PathVariable("label") String label, @RequestParam("earliest") String rfc3339Timestamp) {
		Table<String,TimeFrameItem.Type,Integer> table = HashBasedTable.create();

		
		
		return table;
	}
	
	@RequestMapping(value="/api/detection-points/{label}/grouped", method = RequestMethod.GET)
	@ResponseBody
	public ViewObject groupedDetectionPoints(@PathVariable("label") String label, @RequestParam("earliest") String rfc3339Timestamp, @RequestParam("slices") int slices) {
		DateTime startingTime = DateUtils.fromString(rfc3339Timestamp); 

		Collection<Event> events = facade.findEvents(rfc3339Timestamp);
		
		DateTime now = DateUtils.getCurrentTimestamp();
		
		List<Interval> ranges = Dates.splitRange(startingTime, now, slices);

		Map<String, String> categoryKeyMappings = new HashMap<>();
		categoryKeyMappings.put(MORRIS_ID, label);
		
		// timestamp, category, count
		Map<String, Long> timestampCounts = generateTimestampCounts(ranges, events, label);
		
		ViewObject viewObject = new ViewObject(timestampCounts, label);
		
		return viewObject;
	}
	
	@RequestMapping(value="/api/detection-points/top", method = RequestMethod.GET)
	@ResponseBody
	public Map<String, Long> topDetectionPoints(@RequestParam("earliest") String rfc3339Timestamp, @RequestParam("limit") Long limit) {
		Map<DetectionPoint, Long> map = new HashMap<>();
		
		Collection<Event> events = facade.findEvents(rfc3339Timestamp);
		
		Comparator<Entry<DetectionPoint, Long>> byValue = (entry1, entry2) -> entry1.getValue().compareTo(entry2.getValue());
	    
		for (Event event : events) {
			DetectionPoint detectionPoint = event.getDetectionPoint();
			
			Long count = map.get(detectionPoint);
			
			if (count == null) {
				count = 0L;
			}
			
			count = count + 1L;
			
			map.put(detectionPoint, count);
		}
		
		Map<DetectionPoint, Long> filtered = 
				map
				.entrySet()
				.stream()
				.sorted(byValue.reversed())
				.limit(limit)
				.collect(
					Collectors.toMap(
						entry -> entry.getKey(),
						entry -> entry.getValue()
					)
				);
		
		Map<String, Long> stringFiltered = new HashMap<>();
		
		for(DetectionPoint detectionPoint : filtered.keySet()) {
			stringFiltered.put(gson.toJson(detectionPoint), filtered.get(detectionPoint));
		}
		
		Map<String, Long> sorted = Maps.sortStringsByValue(stringFiltered);
		
		return sorted;
	}
	
	private Map<String, Long> generateTimestampCounts(List<Interval> ranges, Collection<Event> events, String label) {

		Map<String, Long> map = new HashMap<>();

		for (Interval range : ranges) {
			String timestamp = range.getEnd().toString(DATE_FORMAT_STR);

			map.put(timestamp, 0L);
		}

		for (Event event : events) {
			
			if (!event.getDetectionPoint().getLabel().equals(label)) {
				// skip events not for this label
				continue;
			}
			
			DateTime eventDate = DateUtils.fromString(event.getTimestamp());

			intervalLoop: for (Interval range : ranges) {
				if (range.contains(eventDate)) {
					String timestamp = range.getEnd().toString(DATE_FORMAT_STR);

					Long count = map.get(timestamp);

					count = count + 1L;

					map.put(timestamp, count);

					break intervalLoop;
				}
			}
		}

		return map;
	}
	
	static class TimeFrameItem {
		
		private enum TimeUnit { MONTH, WEEK, DAY, SHIFT, HOUR; } 
		
		private enum Type { EVENT, ATTACK } 
		
		private TimeUnit unit;
		private int count;
		private Type type;
		
		public static TimeFrameItem of(int count, TimeUnit unit, Type type) {
			return new TimeFrameItem(count, unit, type);
		}
		
		private TimeFrameItem(int count, TimeUnit unit, Type type) {
			this.count = count;
			this.unit = unit;
			this.type = type;
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
	
	static class ViewObject {
		
		public ViewObject(Map<String, Long> timestampCounts, String label) {

			ykeys.add(MORRIS_ID);
			labels.add(label);

			StringBuilder sb = new StringBuilder();
			sb.append("[");

			int i = 1;
			for (String timestamp : timestampCounts.keySet()) {
				sb.append("{ ");

				sb.append("\"y\": \"" + timestamp + "\"");

				sb.append(", \"" + MORRIS_ID + "\": " + timestampCounts.get(timestamp));

				sb.append(" }");
				
				// attach a comma if not last timestamp
				if (i != timestampCounts.size()) {
					sb.append(", ");
				}

				i++;
			}

			sb.append("]");

			this.data = sb.toString();
		}
		
		private String data = "";
		private String xkey = "y";
		private Collection<String> ykeys = new LinkedList<>();
		private Collection<String> labels = new LinkedList<>();
		
		public String getData() {
			return data;
		}
		public String getXkey() {
			return xkey;
		}
		public Collection<String> getYkeys() {
			return ykeys;
		}
		public Collection<String> getLabels() {
			return labels;
		}
		
	}
	
}
