package org.owasp.appsensor.ui.controller;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.joda.time.DateTime;
import org.joda.time.Interval;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.util.DateUtils;
import org.owasp.appsensor.ui.rest.RestReportingEngineFacade;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;

@Controller
public class DashboardController {
	
	private static final String DATE_FORMAT_STR = "YYYY-MM-dd HH:mm:ss";

	@Autowired
	private RestReportingEngineFacade facade;
	
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
	@RequestMapping(value="/api/events/grouped", method = RequestMethod.GET)
	@ResponseBody
	public ViewObject getGroupedEvents(@RequestParam("earliest") String rfc3339Timestamp, @RequestParam("slices") int slices) {
		DateTime startingTime = DateUtils.fromString(rfc3339Timestamp); 

		Collection<Event> events = facade.findEvents(rfc3339Timestamp);
		
		DateTime now = DateUtils.getCurrentTimestamp();
		
		List<Interval> ranges = splitRange(startingTime, now, slices);

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
	
	private List<Interval> splitRange(final DateTime from, final DateTime to, int slices) {
		List<Interval> ranges = new LinkedList<Interval>();
		
		long millisDifference = to.getMillis() - from.getMillis();
		
		long rangeInMillis = millisDifference / slices;
		
		for(int i = 0; i < slices; i++) {
			long startMillis = from.getMillis();
			
			if (ranges.size() > 0) {
				// add 1 ms to end time of previous range
				startMillis = ranges.get(i - 1).getEndMillis() + 1;
			}
			
			Interval range = new Interval(startMillis, startMillis + rangeInMillis);
			ranges.add(range);
		}
		
		return ranges;
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
	
}
