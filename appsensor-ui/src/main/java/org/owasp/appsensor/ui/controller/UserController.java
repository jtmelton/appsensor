package org.owasp.appsensor.ui.controller;

import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.ui.rest.RestReportingEngineFacade;
import org.owasp.appsensor.ui.utils.Maps;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class UserController {
	
	@Autowired
	RestReportingEngineFacade facade;

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
	
}