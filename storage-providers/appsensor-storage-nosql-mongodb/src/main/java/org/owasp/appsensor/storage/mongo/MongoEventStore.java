package org.owasp.appsensor.storage.mongo;

import java.util.ArrayList;
import java.util.Collection;

import javax.annotation.PostConstruct;
import javax.inject.Named;

import com.google.common.base.Preconditions;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.joda.time.DateTime;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.EventListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.EventStore;
import org.owasp.appsensor.core.util.DateUtils;
import org.slf4j.Logger;

import com.google.gson.Gson;
import com.mongodb.Block;
import com.mongodb.DBObject;
import com.mongodb.MongoClient;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.util.JSON;

/**
 * This is a mongodb implementation of the {@link EventStore}.
 * 
 * Implementations of the {@link EventListener} interface can register with 
 * this class and be notified when new {@link Event}s are added to the data store 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
@Loggable
public class MongoEventStore extends EventStore {

	private MongoCollection<Document> events;
	
	private Gson gson = new Gson();
	
	private Logger logger;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) {
		logger.warn("Security event " + event.getDetectionPoint().getLabel() + " triggered by user: " + event.getUser().getUsername());
		
		String json = gson.toJson(event);
		
		events.insertOne(Document.parse(String.valueOf(JSON.parse(json))));
		
		super.notifyListeners(event);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Event> findEvents(final SearchCriteria criteria) {
		Preconditions.checkNotNull(criteria, "criteria must be non-null");
		
		final Collection<Event> matches = new ArrayList<>();

		Collection<Bson> filters = new ArrayList<>();

		User user = criteria.getUser();
		DetectionPoint detectionPoint = criteria.getDetectionPoint();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds();

		if (user != null) {
			filters.add(Filters.eq("user.username", user.getUsername()));
		}

		if (detectionSystemIds != null && detectionSystemIds.size() > 0) {
			filters.add(Filters.in("detectionSystem.detectionSystemId", detectionSystemIds));
		}

		if(detectionPoint != null) {
			if(detectionPoint.getCategory() != null) {
				filters.add(Filters.eq("detectionPoint.category", detectionPoint.getCategory()));
			}

			if(detectionPoint.getLabel() != null) {
				filters.add(Filters.eq("detectionPoint.label", detectionPoint.getLabel()));
			}
		}

		FindIterable<Document> iterable = events.find(Filters.and(filters));
		
		iterable.forEach(new Block<Document>() {
		    @Override
		    public void apply(final Document document) {

		    	String json = document.toJson();
				Event event = gson.fromJson(json, Event.class);
				
				if (isMatchingEvent(criteria, event)) {
					matches.add(event);
				}
		    }
		});

		return matches;
	}
	
	@PostConstruct
	private void initializeMongo() {
		events = initializeCollection();
		
		if(events == null) {
			events = defaultInitialize();
		}
	}
	
	private MongoCollection<Document> defaultInitialize() {
		MongoCollection<Document> collection = null;
		
		try {
			MongoClient mongoClient = new MongoClient();
			MongoDatabase db = mongoClient.getDatabase("appsensor_db");
			collection = db.getCollection("events");
		} catch (Exception e) {
			if(logger != null) {
				logger.error("Mongo connection could not be made", e);
			}
			e.printStackTrace();
		}
		
		return collection;
	}
	
	/**
	 * Default implementation - override if you want a custom initializer.
	 * 
	 * @return DBCollection you want to write to.
	 */
	public MongoCollection<Document> initializeCollection() {
		return null;
	}
	
}
