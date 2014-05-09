package org.owasp.appsensor.storage;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;

import org.joda.time.DateTime;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.User;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.EventListener;
import org.owasp.appsensor.logging.Loggable;
import org.owasp.appsensor.util.DateUtils;
import org.owasp.appsensor.util.FileUtils;
import org.slf4j.Logger;

import com.google.gson.Gson;

/**
 * This is a reference implementation of the {@link EventStore}.
 * 
 * Implementations of the {@link EventListener} interface can register with 
 * this class and be notified when new {@link Event}s are added to the data store 
 * 
 * This implementation is file-based and has the feature that it will load previous 
 * {@link Event}s if configured to do so.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Named
@Loggable
public class FileBasedEventStore extends EventStore {
	
	private Logger logger;
	
	@SuppressWarnings("unused")
	@Inject
	private AppSensorServer appSensorServer;
	
	public static final String DEFAULT_FILE_PATH = File.separator + "tmp";
	
	public static final String DEFAULT_FILE_NAME = "events.txt";
	
	public static final String FILE_PATH_CONFIGURATION_KEY = "filePath";
	
	public static final String FILE_NAME_CONFIGURATION_KEY = "fileName";
	
	private Gson gson = new Gson();
	
	private Path path = null;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) {
		logger.warn("Security event " + event.getDetectionPoint().getId() + " triggered by user: " + event.getUser().getUsername());
		
		writeEvent(event);
		
		super.notifyListeners(event);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Event> findEvents(SearchCriteria criteria) {
		if (criteria == null) {
			throw new IllegalArgumentException("criteria must be non-null");
		}
		
		Collection<Event> matches = new ArrayList<Event>();
		
		User user = criteria.getUser();
		DetectionPoint detectionPoint = criteria.getDetectionPoint();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds(); 
		DateTime earliest = DateUtils.fromString(criteria.getEarliest());
		
		Collection<Event> events = loadEvents();
		
		for (Event event : events) {
			//check user match if user specified
			boolean userMatch = (user != null) ? user.equals(event.getUser()) : true;
			
			//check detection system match if detection systems specified
			boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
					detectionSystemIds.contains(event.getDetectionSystemId()) : true;
			
			//check detection point match if detection point specified
			boolean detectionPointMatch = (detectionPoint != null) ? 
					detectionPoint.getId().equals(event.getDetectionPoint().getId()) : true;
			
			boolean earliestMatch = (earliest != null) ? earliest.isBefore(DateUtils.fromString(event.getTimestamp())) : true;
			
			if (userMatch && detectionSystemMatch && detectionPointMatch && earliestMatch) {
				matches.add(event);
			}
		}
		
		return matches;
	}
	
	protected void writeEvent(Event event) {
		String json = gson.toJson(event);
		
		try {
			Files.write(getPath(), Arrays.asList(json), StandardCharsets.UTF_8, StandardOpenOption.APPEND, StandardOpenOption.WRITE);
		} catch (IOException e) {
			logger.error("Error occurred loading writing event file to path: " + getPath(), e);
		}
	}
	
	protected Collection<Event> loadEvents() {
		Collection<Event> events = new ArrayList<>();
		
		try {
			Collection<String> lines = Files.readAllLines(getPath());
			
			for (String line : lines) {
				Event event = gson.fromJson(line, Event.class);
				
				events.add(event);
			}
		} catch (IOException e) {
			logger.error("Error occurred loading configured event file from path: " + getPath(), e);
		}
		
		return events;
	}
	
	protected Path getPath() {
		if (path != null && Files.exists(path)) {
			return path;
		}
		
		path = FileUtils.getOrCreateFile(lookupFilePath(), lookupFileName());
		
		return path;
	}
	
	protected String lookupFilePath() {
		return DEFAULT_FILE_PATH;
	}
	
	protected String lookupFileName() {
		return DEFAULT_FILE_NAME;
	}
	
}
