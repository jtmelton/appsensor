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
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.ResponseListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.ResponseStore;
import org.owasp.appsensor.core.util.DateUtils;
import org.slf4j.Logger;

import com.google.gson.Gson;
import com.mongodb.Block;
import com.mongodb.MongoClient;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.util.JSON;

/**
 * This is a mongodb implementation of the {@link ResponseStore}.
 * 
 * Implementations of the {@link ResponseListener} interface can register with 
 * this class and be notified when new {@link Response}s are added to the data store 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
@Loggable
public class MongoResponseStore extends ResponseStore {

	private MongoCollection<Document> responses;
	
	private Gson gson = new Gson();
	
	private Logger logger;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addResponse(Response response) {
		logger.warn("Security response " + response.getAction() + " triggered for user: " + response.getUser().getUsername());

		String json = gson.toJson(response);
		
		responses.insertOne(Document.parse(String.valueOf(JSON.parse(json))));
		
		super.notifyListeners(response);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> findResponses(final SearchCriteria criteria) {
		return findResponses(criteria, loadResponses(criteria));
	}
	
	private Collection<Response> loadResponses(final SearchCriteria criteria) {
		Preconditions.checkNotNull(criteria, "criteria must be non-null");

		final Collection<Response> matches = new ArrayList<>();

		Collection<Bson> filters = new ArrayList<>();

		User user = criteria.getUser();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds();


		if (user != null) {
			filters.add(Filters.eq("user.username", user.getUsername()));
		}

		if (detectionSystemIds != null && detectionSystemIds.size() > 0) {
			filters.add(Filters.in("detectionSystem.detectionSystemId", detectionSystemIds));
		}

		FindIterable<Document> iterable = responses.find(Filters.and(filters));

		iterable.forEach(new Block<Document>() {
			@Override
			public void apply(final Document document) {

				String json = document.toJson();
				Response response = gson.fromJson(json, Response.class);

				matches.add(response);
			}
		});

		return matches;
	}
	
	@PostConstruct
	private void initializeMongo() {
		responses = initializeCollection();
		
		if(responses == null) {
			responses = defaultInitialize();
		}
	}
	
	private MongoCollection<Document> defaultInitialize() {
		MongoCollection<Document> collection = null;
		
		try {
			MongoClient mongoClient = new MongoClient();
			MongoDatabase db = mongoClient.getDatabase("appsensor_db");
			collection = db.getCollection("responses");
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
