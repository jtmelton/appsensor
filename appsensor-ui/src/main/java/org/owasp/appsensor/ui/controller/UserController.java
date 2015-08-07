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
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
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
public class UserController {
	
	@Autowired
	private RestReportingEngineFacade facade;

	private final Gson gson = new Gson();
	
	private final static String MORRIS_EVENTS_ID = "events1";
	private final static String MORRIS_ATTACKS_ID = "attacks1";
	private final static String MORRIS_RESPONSES_ID = "responses1";
	private final static String EVENTS_LABEL = "Events";
	private final static String ATTACKS_LABEL = "Attacks";
	private final static String RESPONSES_LABEL = "Responses";
	
	private static final String DATE_FORMAT_STR = "YYYY-MM-dd HH:mm:ss";
	
	@RequestMapping(value="/api/users/{username}/all", method = RequestMethod.GET)
	@ResponseBody
	public Map<String,Object> allContent(@PathVariable("username") String username, @RequestParam("earliest") String rfc3339Timestamp, @RequestParam Long limit, @RequestParam int slices) { 
		Map<String,Object> allContent = new HashMap<>();
		
		allContent.put("byTimeFrame", byTimeFrame(username));
		allContent.put("recentEvents", recentEvents(username, rfc3339Timestamp, limit));
		allContent.put("recentAttacks", recentAttacks(username, rfc3339Timestamp, limit));
		allContent.put("recentResponses", recentResponses(username, rfc3339Timestamp, limit));
		allContent.put("byClientApplication", byClientApplication(username, rfc3339Timestamp));
		allContent.put("groupedUsers", groupedUsers(username, rfc3339Timestamp, slices));
		allContent.put("activeResponses", activeResponses(username, rfc3339Timestamp));
		
		return allContent;
	}
	
	@RequestMapping(value="/api/users/{username}/active-responses", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Response> activeResponses(@PathVariable("username") String username, @RequestParam("earliest") String rfc3339Timestamp) {
		Comparator<Response> byDate = (entry1, entry2) -> DateUtils.fromString(entry1.getTimestamp()).compareTo(DateUtils.fromString(entry2.getTimestamp()));
		
		Collection<Response> activeResponses = facade.findResponses(rfc3339Timestamp)
				.stream()
				.filter(r -> username.equals(r.getUser().getUsername()))
				.filter(Response::isActive)
				.sorted(byDate)
				.collect(Collectors.toList());
				
		return activeResponses;
	}
	@RequestMapping(value="/api/users/{username}/by-time-frame", method = RequestMethod.GET)
	@ResponseBody
	public Collection<TimeFrameItem> byTimeFrame(@PathVariable("username") String username) {
		Collection<TimeFrameItem> items = new ArrayList<>();
		
		DateTime now = DateUtils.getCurrentTimestamp();
		DateTime monthAgo = now.minusMonths(1);
		DateTime weekAgo = now.minusWeeks(1);
		DateTime dayAgo = now.minusDays(1);
		DateTime shiftAgo = now.minusHours(8);
		DateTime hourAgo = now.minusHours(1);
		
		long monthAgoEventCount = facade.countEventsByUser(monthAgo.toString(), username);
		long weekAgoEventCount = facade.countEventsByUser(weekAgo.toString(), username);
		long dayAgoEventCount = facade.countEventsByUser(dayAgo.toString(), username);
		long shiftAgoEventCount = facade.countEventsByUser(shiftAgo.toString(), username);
		long hourAgoEventCount = facade.countEventsByUser(hourAgo.toString(), username);
		
		long monthAgoResponseCount = facade.countResponsesByUser(monthAgo.toString(), username);
		long weekAgoResponseCount = facade.countResponsesByUser(weekAgo.toString(), username);
		long dayAgoResponseCount = facade.countResponsesByUser(dayAgo.toString(), username);
		long shiftAgoResponseCount = facade.countResponsesByUser(shiftAgo.toString(), username);
		long hourAgoResponseCount = facade.countResponsesByUser(hourAgo.toString(), username);
	
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

	@RequestMapping(value="/api/users/{username}/latest-events", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Event> recentEvents(@PathVariable("username") String username, @RequestParam("earliest") String rfc3339Timestamp, @RequestParam("limit") Long limit) {
		Comparator<Event> byDate = (entry1, entry2) -> DateUtils.fromString(entry1.getTimestamp()).compareTo(DateUtils.fromString(entry2.getTimestamp()));
		
		List<Event> dateSorted = facade.findEvents(rfc3339Timestamp)
				.stream()
				.filter(e -> username.equals(e.getUser().getUsername()))
				.sorted(byDate)
				.collect(Collectors.toList());
				
		Collections.reverse(dateSorted);
		Collection<Event> events = dateSorted.stream().limit(limit).collect(Collectors.toList());

		return events;
	}
	
	@RequestMapping(value="/api/users/{username}/latest-attacks", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Attack> recentAttacks(@PathVariable("username") String username, @RequestParam("earliest") String rfc3339Timestamp, @RequestParam("limit") Long limit) {
		Comparator<Attack> byDate = (entry1, entry2) -> DateUtils.fromString(entry1.getTimestamp()).compareTo(DateUtils.fromString(entry2.getTimestamp()));
		
		List<Attack> dateSorted = facade.findAttacks(rfc3339Timestamp)
				.stream()
				.filter(a -> username.equals(a.getUser().getUsername()))
				.sorted(byDate)
				.collect(Collectors.toList());
				
		Collections.reverse(dateSorted);
		Collection<Attack> attacks = dateSorted.stream().limit(limit).collect(Collectors.toList());

		return attacks;
	}
	
	@RequestMapping(value="/api/users/{username}/latest-responses", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Response> recentResponses(@PathVariable("username") String username, @RequestParam("earliest") String rfc3339Timestamp, @RequestParam("limit") Long limit) {
		Comparator<Response> byDate = (entry1, entry2) -> DateUtils.fromString(entry1.getTimestamp()).compareTo(DateUtils.fromString(entry2.getTimestamp()));
		
		List<Response> dateSorted = facade.findResponses(rfc3339Timestamp)
				.stream()
				.filter(r -> username.equals(r.getUser().getUsername()))
				.sorted(byDate)
				.collect(Collectors.toList());
				
		Collections.reverse(dateSorted);
		Collection<Response> responses = dateSorted.stream().limit(limit).collect(Collectors.toList());

		return responses;
	}
	
	// seen by these client apps
	@RequestMapping(value="/api/users/{username}/by-client-application", method = RequestMethod.GET)
	@ResponseBody
	public String byClientApplication(@PathVariable("username") String username, @RequestParam("earliest") String rfc3339Timestamp) {
		Table<String,TimeFrameItem.Type,Long> table = HashBasedTable.create();

		Collection<Event> events = facade.findEvents(rfc3339Timestamp).stream().filter(e -> username.equals(e.getUser().getUsername())).collect(Collectors.toList());
		Collection<Attack> attacks = facade.findAttacks(rfc3339Timestamp).stream().filter(a -> username.equals(a.getUser().getUsername())).collect(Collectors.toList());
		Collection<Response> responses = facade.findResponses(rfc3339Timestamp).stream().filter(r -> username.equals(r.getUser().getUsername())).collect(Collectors.toList());
		
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
		
		for(Response response : responses) {
			Long count = table.get(response.getDetectionSystem().getDetectionSystemId(), TimeFrameItem.Type.RESPONSE);
			
			if (count == null) {
				count = 0L;
			}
			
			count = count + 1L;
			
			table.put(response.getDetectionSystem().getDetectionSystemId(), TimeFrameItem.Type.RESPONSE, count);
		}
		
		return gson.toJson(table);
	}
	
	@RequestMapping(value="/api/users/{username}/grouped", method = RequestMethod.GET)
	@ResponseBody
	public ViewObject groupedUsers(@PathVariable("username") String username, @RequestParam("earliest") String rfc3339Timestamp, @RequestParam("slices") int slices) {
		DateTime startingTime = DateUtils.fromString(rfc3339Timestamp); 

		Collection<Event> events = facade.findEvents(rfc3339Timestamp).stream().filter(e -> username.equals(e.getUser().getUsername())).collect(Collectors.toList());
		Collection<Attack> attacks = facade.findAttacks(rfc3339Timestamp).stream().filter(a -> username.equals(a.getUser().getUsername())).collect(Collectors.toList());
		Collection<Response> responses = facade.findResponses(rfc3339Timestamp).stream().filter(r -> username.equals(r.getUser().getUsername())).collect(Collectors.toList());
		
		DateTime now = DateUtils.getCurrentTimestamp();
		
		List<Interval> ranges = Dates.splitRange(startingTime, now, slices);

		Map<String, String> categoryKeyMappings = new HashMap<>();
		categoryKeyMappings.put(EVENTS_LABEL, MORRIS_EVENTS_ID);
		categoryKeyMappings.put(ATTACKS_LABEL, MORRIS_ATTACKS_ID);
		categoryKeyMappings.put(RESPONSES_LABEL, MORRIS_RESPONSES_ID);
		
		// timestamp, category, count
		Table<String, String, Long> timestampCounts = generateTimestampCounts(ranges, events, attacks, responses);
		
		ViewObject viewObject = new ViewObject(timestampCounts, categoryKeyMappings);
		
		return viewObject;
	}
	
	@RequestMapping(value="/api/users/top", method = RequestMethod.GET)
	@ResponseBody
	public Map<String, Long> topUsers(@RequestParam("earliest") String rfc3339Timestamp, @RequestParam("limit") Long limit) {
		Map<String, Long> map = new HashMap<>();
		
		Collection<Event> events = facade.findEvents(rfc3339Timestamp);
		
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
	
	private Table<String, String, Long> generateTimestampCounts(List<Interval> ranges, Collection<Event> events, Collection<Attack> attacks, Collection<Response> responses) {

		Table<String, String, Long> table = HashBasedTable.create();

		for (Interval range : ranges) {
			String timestamp = range.getEnd().toString(DATE_FORMAT_STR);
			
			table.put(timestamp, EVENTS_LABEL, 0L);
			table.put(timestamp, ATTACKS_LABEL, 0L);
			table.put(timestamp, RESPONSES_LABEL, 0L);
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
		
		for (Response response : responses) {
			DateTime attackDate = DateUtils.fromString(response.getTimestamp());
			
			intervalLoop: for(Interval range : ranges) {
				if (range.contains(attackDate)) {
					String timestamp = range.getEnd().toString(DATE_FORMAT_STR);

					Long count = table.get(timestamp, RESPONSES_LABEL);
					
					count = count + 1L;
					
					table.put(timestamp, RESPONSES_LABEL, count);
					
					break intervalLoop;
				}
			}
		}
		
		return table;
	}
	
	static class TimeFrameItem {
		
		private enum TimeUnit { MONTH, WEEK, DAY, SHIFT, HOUR; } 
		
		private enum Type { EVENT, ATTACK, RESPONSE } 
		
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