package org.owasp.appsensor.ui.controller;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.joda.time.DateTime;
import org.joda.time.Interval;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.util.DateUtils;
import org.owasp.appsensor.ui.rest.RestReportingEngineFacade;
import org.owasp.appsensor.ui.utils.Dates;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;
import com.google.gson.Gson;

@Controller
public class DashboardController {
	
	private static final String DATE_FORMAT_STR = "YYYY-MM-dd HH:mm:ss";

	@Autowired
	private RestReportingEngineFacade facade;
	
	@Autowired
	private UserController userController;

	@Autowired
	private DetectionPointController detectionPointController;
	
	private final static Gson gson = new Gson();
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/dashboard/all", method = RequestMethod.GET)
	@ResponseBody
	public Map<String,Object> allContent(@RequestParam("earliest") String rfc3339Timestamp, @RequestParam("slices") int slices, @RequestParam("limit") Long limit) {
		Map<String,Object> allContent = new HashMap<>();
		
		allContent.put("activeResponses", activeResponses(rfc3339Timestamp, limit));
		allContent.put("byTimeFrame", byTimeFrame());
		allContent.put("byCategory", byCategory(rfc3339Timestamp));
		allContent.put("groupedEvents", groupedEvents(rfc3339Timestamp, slices));
		allContent.put("topUsers", userController.topUsers(rfc3339Timestamp, limit));
		allContent.put("topDetectionPoints", detectionPointController.topDetectionPoints(rfc3339Timestamp, limit));
		
		return allContent;
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/responses/active", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Response> activeResponses(@RequestParam("earliest") String rfc3339Timestamp, @RequestParam("limit") Long limit) {
		Collection<Response> responses = facade.findResponses(rfc3339Timestamp);

		Long computedLimit = (limit != null) ? limit : Integer.MAX_VALUE;
		Collection<Response> activeResponses = responses.stream().filter(Response::isActive).limit(computedLimit).collect(Collectors.toSet());
		
		return activeResponses;
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/dashboard/by-time-frame", method = RequestMethod.GET)
	@ResponseBody
	public Collection<TimeFrameItem> byTimeFrame() {
		Collection<TimeFrameItem> items = new ArrayList<>();
		
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
		
		items.add(TimeFrameItem.of(monthAgoEventCount, TimeFrameItem.TimeUnit.MONTH, TimeFrameItem.Type.EVENT));
		items.add(TimeFrameItem.of(monthAgoResponseCount, TimeFrameItem.TimeUnit.MONTH, TimeFrameItem.Type.RESPONSE));
		items.add(TimeFrameItem.of(weekAgoEventCount,  TimeFrameItem.TimeUnit.WEEK, TimeFrameItem.Type.EVENT));
		items.add(TimeFrameItem.of(weekAgoResponseCount,  TimeFrameItem.TimeUnit.WEEK, TimeFrameItem.Type.RESPONSE));
		items.add(TimeFrameItem.of(dayAgoEventCount,   TimeFrameItem.TimeUnit.DAY, TimeFrameItem.Type.EVENT));
		items.add(TimeFrameItem.of(dayAgoResponseCount,   TimeFrameItem.TimeUnit.DAY, TimeFrameItem.Type.RESPONSE));
		items.add(TimeFrameItem.of(shiftAgoEventCount, TimeFrameItem.TimeUnit.SHIFT, TimeFrameItem.Type.EVENT));
		items.add(TimeFrameItem.of(shiftAgoResponseCount, TimeFrameItem.TimeUnit.SHIFT, TimeFrameItem.Type.RESPONSE));
		items.add(TimeFrameItem.of(hourAgoEventCount,  TimeFrameItem.TimeUnit.HOUR, TimeFrameItem.Type.EVENT));
		items.add(TimeFrameItem.of(hourAgoResponseCount,  TimeFrameItem.TimeUnit.HOUR, TimeFrameItem.Type.RESPONSE));

		return items;
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/dashboard/by-category", method = RequestMethod.GET)
	@ResponseBody
	public Collection<CategoryItem> byCategory(@RequestParam("earliest") String rfc3339Timestamp) {
		Collection<CategoryItem> items = new ArrayList<>();

		final Long maxItems = 5L;
		
		final Collection<Event> events = facade.findEvents(rfc3339Timestamp);
		final Collection<Attack> attacks = facade.findAttacks(rfc3339Timestamp);
		
		for (String category : facade.getConfiguredDetectionPointCategories()) {
			final List<Event> categoryEvents = events.stream().filter(e -> e.getDetectionPoint().getCategory().equals(category)).collect(Collectors.toList());
			final List<Attack> categoryAttacks = attacks.stream().filter(a -> a.getDetectionPoint().getCategory().equals(category)).collect(Collectors.toList());
			
			Table<String, CategoryItem.Type, Long> countByLabel = HashBasedTable.create();
			
			for (Event event : categoryEvents) {
				String label = event.getDetectionPoint().getLabel();
				
				Long count = countByLabel.get(label, CategoryItem.Type.EVENT);
				
				if (count == null) {
					count = 0L;
				}
				
				count = count + 1L;
				
				countByLabel.put(label, CategoryItem.Type.EVENT, count);
			}
			
			for (Attack attack : categoryAttacks) {
				String label = attack.getDetectionPoint().getLabel();
				
				Long count = countByLabel.get(label, CategoryItem.Type.ATTACK);
				
				if (count == null) {
					count = 0L;
				}
				
				count = count + 1L;
				
				countByLabel.put(label, CategoryItem.Type.ATTACK, count);
			}
			
			final Collection<Event> latestEvents = latest(categoryEvents, maxItems);
			final Collection<Attack> latestAttacks = latest(categoryAttacks, maxItems);
			
			items.add(CategoryItem.of(category, categoryEvents.size(), categoryAttacks.size(), countByLabel, latestEvents, latestAttacks));
		}
		
		return items;
	}
	
	private <T extends Object> Collection<T> latest(List<T> original, Long limit) {
		List<T> list = original.stream().collect(Collectors.toList());
		Collections.reverse(list);
		Collection<T> latest = list.stream().limit(limit).collect(Collectors.toList());
		
		return latest;
	}
	
	// pull events from "earliest" until now 
	// build "slices" # (e.g. 20) of equal time ranges from "earliest" to now
	// group events by time frame. 
	// 
	// example: "earliest" is 20 days ago, and "slices" is 20. 
	// there would be a time range for each day, and you would count how many events applied to that day grouped by detection point category
	// something like 
	// [ 
	//	day1/cat1/5, day1/cat2/1, day1/cat3/14,
	//  day2/cat1/7, day2/cat2/0, day2/cat3/47,
	//  day3/cat1/2, day3/cat2/3, day3/cat3/53,
	//  ...
	// ]
	// 
	// this function drives the dashboard and is specifically formatted for an morris.js graph
	// 
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/events/grouped", method = RequestMethod.GET)
	@ResponseBody
	public ViewObject groupedEvents(@RequestParam("earliest") String rfc3339Timestamp, @RequestParam("slices") int slices) {
		DateTime startingTime = DateUtils.fromString(rfc3339Timestamp); 

		Collection<Event> events = facade.findEvents(rfc3339Timestamp);
		
		DateTime now = DateUtils.getCurrentTimestamp();
		
		List<Interval> ranges = Dates.splitRange(startingTime, now, slices);

		Map<String, String> categoryKeyMappings = generateCategoryKeyMappings();
		
		// timestamp, category, count
		Table<String, String, Long> timestampCategoryCounts = generateTimestampCategoryCounts(ranges, categoryKeyMappings, events);
		
		ViewObject viewObject = new ViewObject(timestampCategoryCounts, categoryKeyMappings);
		
		return viewObject;
	}
	
	private Table<String, String, Long> generateTimestampCategoryCounts(List<Interval> ranges,
																		Map<String, String> categoryKeyMappings,
																		Collection<Event> events) {
		
		Table<String, String, Long> table = HashBasedTable.create();
		
		for (Interval range : ranges) {
			String timestamp = range.getEnd().toString(DATE_FORMAT_STR);
			
			for (String category : categoryKeyMappings.keySet()) {
				table.put(timestamp, category, 0L);
			}
		}
		
		for (Event event : events) {
			DateTime eventDate = DateUtils.fromString(event.getTimestamp());
			
			intervalLoop: for(Interval range : ranges) {
				if (range.contains(eventDate)) {
					String timestamp = range.getEnd().toString(DATE_FORMAT_STR);
					String category = event.getDetectionPoint().getCategory();

					Long count = table.get(timestamp, category);
					
					count = count + 1L;
					
					table.put(timestamp, category, count);
					
					break intervalLoop;
				}
			}
		}
		
		return table;
	}
	
	private Map<String, String> generateCategoryKeyMappings() {
		Map<String, String> categoryKeyMappings = new HashMap<>();
		
		int i = 1;
		for (String category : facade.getConfiguredDetectionPointCategories()) {
			categoryKeyMappings.put(category, "a" + String.valueOf(i));
			i++;
		}
		
		return categoryKeyMappings;
	}
	
	static class ViewObject {
		
		public ViewObject(	Table<String, String, Long> timestampCategoryCounts, 
							Map<String, String> categoryKeyMappings) {

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
	
	static class TimeFrameItem {
		
		private enum TimeUnit { MONTH, WEEK, DAY, SHIFT, HOUR; } 
		
		private enum Type { EVENT, RESPONSE } 
		
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
	
	static class CategoryItem {
		
		private final String category;
		private final int eventCount;
		private final int attackCount;
		
		// label name, type, count
		private final Table<String, Type, Long> countByLabel;

		private enum Type { EVENT, ATTACK }
		
		private final Collection<Event> recentEvents;
		private final Collection<Attack> recentAttacks;
		
		public static CategoryItem of(
				String category, 
				int eventCount, 
				int attackCount, 
				Table<String, Type, Long> countByLabel,
				Collection<Event> recentEvents,
				Collection<Attack> recentAttacks) {
			return new CategoryItem(category, eventCount, attackCount, countByLabel, recentEvents, recentAttacks);
		}
		
		private CategoryItem(
				String category, 
				int eventCount, 
				int attackCount, 
				Table<String, Type, Long> countByLabel,
				Collection<Event> recentEvents,
				Collection<Attack> recentAttacks) {
			this.category = category;
			this.eventCount = eventCount;
			this.attackCount = attackCount;
			this.countByLabel = countByLabel;
			this.recentEvents = recentEvents;
			this.recentAttacks = recentAttacks;
		}
		
		public String getCategory() {
			return category;
		}

		public String getCountByLabel() {
			return gson.toJson(countByLabel);
		}

		public Collection<Event> getRecentEvents() {
			return recentEvents;
		}

		public Collection<Attack> getRecentAttacks() {
			return recentAttacks;
		}

		public int getEventCount() {
			return eventCount;
		}
		
		public int getAttackCount() {
			return attackCount;
		}
		
	}
}
