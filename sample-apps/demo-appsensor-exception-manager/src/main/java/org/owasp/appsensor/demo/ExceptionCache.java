package org.owasp.appsensor.demo;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.owasp.appsensor.core.Event;

public class ExceptionCache {
	
	private final static ConcurrentMap<String, Collection<Event>> exceptions = new ConcurrentHashMap<String, Collection<Event>>();

	public static Collection<Event> findAll() {
		Collection<Event> all = new ArrayList<>();
		
		for(String key : exceptions.keySet()) {
			all.addAll(exceptions.get(key));
		}
		
		return all;
	}

	public static void save(Event event) {
		String name = event.getDetectionPoint().getLabel();
		
		Collection<Event> events = exceptions.get(name);
		
		if(events == null) {
			events = new ArrayList<>();
		}
		
		events.add(event);
		
		exceptions.put(name, events);
		
		System.err.println("ExceptionCache: added event for [" + name + 
				"] -> total events now at [" + findAll().size() + "]");
	}

	public static Collection<Event> findByType(String type) {
		return exceptions.get(type);
	}
}
