package org.owasp.appsensor.ui.controller;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.joda.time.DateTime;
import org.joda.time.Interval;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.util.DateUtils;
import org.owasp.appsensor.ui.rest.RestReportingEngineFacade;
import org.owasp.appsensor.ui.utils.Dates;
import org.owasp.appsensor.ui.utils.Maps;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
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
	
	private final static String MORRIS_EVENTS_ID = "events1";
	private final static String MORRIS_ATTACKS_ID = "attacks1";
	private final static String EVENTS_LABEL = "Events";
	private final static String ATTACKS_LABEL = "Attacks";
	
	private static final String DATE_FORMAT_STR = "YYYY-MM-dd HH:mm:ss";
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/detection-points/{label}/all", method = RequestMethod.GET)
	@ResponseBody
	public Map<String,Object> allContent(@PathVariable("label") String label, @RequestParam("earliest") String rfc3339Timestamp, @RequestParam Long limit, @RequestParam int slices) { 
		Map<String,Object> allContent = new HashMap<>();
		
		allContent.put("byTimeFrame", byTimeFrame(label));
		allContent.put("configuration", configuration(label));
		allContent.put("recentEvents", recentEvents(label, rfc3339Timestamp, limit));
		allContent.put("recentAttacks", recentAttacks(label, rfc3339Timestamp, limit));
		allContent.put("byClientApplication", byClientApplication(label, rfc3339Timestamp));
		allContent.put("topUsers", topUsers(label, rfc3339Timestamp, limit));
		allContent.put("groupedDetectionPoints", groupedDetectionPoints(label, rfc3339Timestamp, slices));

		return allContent;
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/detection-points/{label}/by-time-frame", method = RequestMethod.GET)
	@ResponseBody
	public Collection<TimeFrameItem> byTimeFrame(@PathVariable("label") String label) {
		Collection<TimeFrameItem> items = new ArrayList<>();
		
		DateTime now = DateUtils.getCurrentTimestamp();
		DateTime monthAgo = now.minusMonths(1);
		DateTime weekAgo = now.minusWeeks(1);
		DateTime dayAgo = now.minusDays(1);
		DateTime shiftAgo = now.minusHours(8);
		DateTime hourAgo = now.minusHours(1);
		
		long monthAgoEventCount = facade.countEventsByLabel(monthAgo.toString(), label);
		long weekAgoEventCount = facade.countEventsByLabel(weekAgo.toString(), label);
		long dayAgoEventCount = facade.countEventsByLabel(dayAgo.toString(), label);
		long shiftAgoEventCount = facade.countEventsByLabel(shiftAgo.toString(), label);
		long hourAgoEventCount = facade.countEventsByLabel(hourAgo.toString(), label);
		
		long monthAgoResponseCount = facade.countAttacksByLabel(monthAgo.toString(), label);
		long weekAgoResponseCount = facade.countAttacksByLabel(weekAgo.toString(), label);
		long dayAgoResponseCount = facade.countAttacksByLabel(dayAgo.toString(), label);
		long shiftAgoResponseCount = facade.countAttacksByLabel(shiftAgo.toString(), label);
		long hourAgoResponseCount = facade.countAttacksByLabel(hourAgo.toString(), label);
	
		items.add(TimeFrameItem.of(monthAgoEventCount, TimeFrameItem.TimeUnit.MONTH, TimeFrameItem.Type.EVENT));
		items.add(TimeFrameItem.of(monthAgoResponseCount, TimeFrameItem.TimeUnit.MONTH, TimeFrameItem.Type.ATTACK));
		items.add(TimeFrameItem.of(weekAgoEventCount,  TimeFrameItem.TimeUnit.WEEK, TimeFrameItem.Type.EVENT));
		items.add(TimeFrameItem.of(weekAgoResponseCount,  TimeFrameItem.TimeUnit.WEEK, TimeFrameItem.Type.ATTACK));
		items.add(TimeFrameItem.of(dayAgoEventCount,   TimeFrameItem.TimeUnit.DAY, TimeFrameItem.Type.EVENT));
		items.add(TimeFrameItem.of(dayAgoResponseCount,   TimeFrameItem.TimeUnit.DAY, TimeFrameItem.Type.ATTACK));
		items.add(TimeFrameItem.of(shiftAgoEventCount, TimeFrameItem.TimeUnit.SHIFT, TimeFrameItem.Type.EVENT));
		items.add(TimeFrameItem.of(shiftAgoResponseCount, TimeFrameItem.TimeUnit.SHIFT, TimeFrameItem.Type.ATTACK));
		items.add(TimeFrameItem.of(hourAgoEventCount,  TimeFrameItem.TimeUnit.HOUR, TimeFrameItem.Type.EVENT));
		items.add(TimeFrameItem.of(hourAgoResponseCount,  TimeFrameItem.TimeUnit.HOUR, TimeFrameItem.Type.ATTACK));

		return items;
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/detection-points/{label}/configuration", method = RequestMethod.GET)
	@ResponseBody
	public String configuration(@PathVariable("label") String label) {
		return gson.toJson(facade.getConfiguredDetectionPoints(label));
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/detection-points/{label}/latest-events", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Event> recentEvents(@PathVariable("label") String label, @RequestParam("earliest") String rfc3339Timestamp, @RequestParam("limit") Long limit) {
		Comparator<Event> byDate = (entry1, entry2) -> DateUtils.fromString(entry1.getTimestamp()).compareTo(DateUtils.fromString(entry2.getTimestamp()));
		
		List<Event> dateSorted = facade.findEvents(rfc3339Timestamp)
				.stream()
				.filter(e -> label.equals(e.getDetectionPoint().getLabel()))
				.sorted(byDate)
				.collect(Collectors.toList());
				
		Collections.reverse(dateSorted);
		Collection<Event> events = dateSorted.stream().limit(limit).collect(Collectors.toList());

		return events;
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/detection-points/{label}/latest-attacks", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Attack> recentAttacks(@PathVariable("label") String label, @RequestParam("earliest") String rfc3339Timestamp, @RequestParam("limit") Long limit) {
		Comparator<Attack> byDate = (entry1, entry2) -> DateUtils.fromString(entry1.getTimestamp()).compareTo(DateUtils.fromString(entry2.getTimestamp()));
		
		List<Attack> dateSorted = facade.findAttacks(rfc3339Timestamp)
				.stream()
				.filter(a -> label.equals(a.getDetectionPoint().getLabel()))
				.sorted(byDate)
				.collect(Collectors.toList());
				
		Collections.reverse(dateSorted);
		Collection<Attack> attacks = dateSorted.stream().limit(limit).collect(Collectors.toList());

		return attacks;
	}
	
	// seen by these client apps
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/detection-points/{label}/by-client-application", method = RequestMethod.GET)
	@ResponseBody
	public String byClientApplication(@PathVariable("label") String label, @RequestParam("earliest") String rfc3339Timestamp) {
		Table<String,TimeFrameItem.Type,Long> table = HashBasedTable.create();

		Collection<Event> events = facade.findEvents(rfc3339Timestamp).stream().filter(e -> label.equals(e.getDetectionPoint().getLabel())).collect(Collectors.toList());
		Collection<Attack> attacks = facade.findAttacks(rfc3339Timestamp).stream().filter(a -> label.equals(a.getDetectionPoint().getLabel())).collect(Collectors.toList());
		
		for(Event event : events) {
			Long count = table.get(event.getDetectionSystem().getDetectionSystemId(), TimeFrameItem.Type.EVENT);
			
			if (count == null) {
				count = 0L;
			}
			
			count = count + 1L;
			
			table.put(event.getDetectionSystem().getDetectionSystemId(), TimeFrameItem.Type.EVENT, count);
		}
		
		for(Attack attack : attacks) {
			Long count = table.get(attack.getDetectionSystem().getDetectionSystemId(), TimeFrameItem.Type.ATTACK);
			
			if (count == null) {
				count = 0L;
			}
			
			count = count + 1L;
			
			table.put(attack.getDetectionSystem().getDetectionSystemId(), TimeFrameItem.Type.ATTACK, count);
		}
		
		return gson.toJson(table);
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/detection-points/{label}/top-users", method = RequestMethod.GET)
	@ResponseBody
	public Map<String, Long> topUsers(@PathVariable("label") String label, @RequestParam("earliest") String rfc3339Timestamp, @RequestParam("limit") Long limit) {
		Map<String, Long> map = new HashMap<>();
		
		Collection<Event> events = facade.findEvents(rfc3339Timestamp).stream().filter(e -> label.equals(e.getDetectionPoint().getLabel())).collect(Collectors.toList());
		
		Comparator<Entry<String, Long>> byValue = (entry1, entry2) -> entry1.getValue().compareTo(entry2.getValue());
	    
		for (Event event : events) {
			String username = event.getUser().getUsername();
			
			Long count = map.get(username);
			
			if (count == null) {
				count = 0L;
			}
			
			count = count + 1L;
			
			map.put(username, count);
		}
		
		Map<String, Long> filtered = 
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
		
		Map<String, Long> sorted = Maps.sortStringsByValue(filtered);
		
		return sorted;
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/detection-points/{label}/grouped", method = RequestMethod.GET)
	@ResponseBody
	public ViewObject groupedDetectionPoints(@PathVariable("label") String label, @RequestParam("earliest") String rfc3339Timestamp, @RequestParam("slices") int slices) {
		DateTime startingTime = DateUtils.fromString(rfc3339Timestamp); 

		Collection<Event> events = facade.findEvents(rfc3339Timestamp).stream().filter(e -> label.equals(e.getDetectionPoint().getLabel())).collect(Collectors.toList());
		Collection<Attack> attacks = facade.findAttacks(rfc3339Timestamp).stream().filter(a -> label.equals(a.getDetectionPoint().getLabel())).collect(Collectors.toList());
		
		DateTime now = DateUtils.getCurrentTimestamp();
		
		List<Interval> ranges = Dates.splitRange(startingTime, now, slices);

		Map<String, String> categoryKeyMappings = new HashMap<>();
		categoryKeyMappings.put(EVENTS_LABEL, MORRIS_EVENTS_ID);
		categoryKeyMappings.put(ATTACKS_LABEL, MORRIS_ATTACKS_ID);
		
		// timestamp, category, count
		Table<String, String, Long> timestampCounts = generateTimestampCounts(ranges, events, attacks);
		
		ViewObject viewObject = new ViewObject(timestampCounts, categoryKeyMappings);
		
		return viewObject;
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
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
	
	private Table<String, String, Long> generateTimestampCounts(List<Interval> ranges, Collection<Event> events, Collection<Attack> attacks) {

		Table<String, String, Long> table = HashBasedTable.create();

		for (Interval range : ranges) {
			String timestamp = range.getEnd().toString(DATE_FORMAT_STR);
			
			table.put(timestamp, EVENTS_LABEL, 0L);
			table.put(timestamp, ATTACKS_LABEL, 0L);
		}
		
		for (Event event : events) {
			DateTime eventDate = DateUtils.fromString(event.getTimestamp());
			
			intervalLoop: for(Interval range : ranges) {
				if (range.contains(eventDate)) {
					String timestamp = range.getEnd().toString(DATE_FORMAT_STR);

					Long count = table.get(timestamp, EVENTS_LABEL);
					
					count = count + 1L;
					
					table.put(timestamp, EVENTS_LABEL, count);
					
					break intervalLoop;
				}
			}
		}
		
		for (Attack attack : attacks) {
			DateTime attackDate = DateUtils.fromString(attack.getTimestamp());
			
			intervalLoop: for(Interval range : ranges) {
				if (range.contains(attackDate)) {
					String timestamp = range.getEnd().toString(DATE_FORMAT_STR);

					Long count = table.get(timestamp, ATTACKS_LABEL);
					
					count = count + 1L;
					
					table.put(timestamp, ATTACKS_LABEL, count);
					
					break intervalLoop;
				}
			}
		}
		
		return table;
	}
	
	static class TimeFrameItem {
		
		private enum TimeUnit { MONTH, WEEK, DAY, SHIFT, HOUR; } 
		
		private enum Type { EVENT, ATTACK } 
		
		private TimeUnit unit;
		private long count;
		private Type type;
		
		public static TimeFrameItem of(long count, TimeUnit unit, Type type) {
			return new TimeFrameItem(count, unit, type);
		}
		
		private TimeFrameItem(long count, TimeUnit unit, Type type) {
			this.count = count;
			this.unit = unit;
			this.type = type;
		}

		public TimeUnit getUnit() {
			return unit;
		}

		public long getCount() {
			return count;
		}
		
		public Type getType() {
			return type;
		}
		
	}
	
	static class ViewObject {

		public ViewObject(Table<String, String, Long> timestampCategoryCounts, Map<String, String> categoryKeyMappings) {

			for (String category : categoryKeyMappings.keySet()) {
				ykeys.add(categoryKeyMappings.get(category));
				labels.add(category);
			}

			StringBuilder sb = new StringBuilder();
			sb.append("[");

			int i = 1;
			for (String timestamp : timestampCategoryCounts.rowKeySet()) {
				sb.append("{ ");

				sb.append("\"y\": \"" + timestamp + "\"");

				Map<String, Long> categoryCountMap = timestampCategoryCounts.row(timestamp);
				for (String category : categoryCountMap.keySet()) {
					sb.append(", \"" + categoryKeyMappings.get(category) + "\": " + categoryCountMap.get(category));
				}

				sb.append(" }");
				// attach a comma if not last timestamp
				if (i != timestampCategoryCounts.rowKeySet().size()) {
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
