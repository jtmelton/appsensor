package org.owasp.appsensor.ui.rest;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.KeyValuePair;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.ui.handler.AssociatedApplicationsContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

@Service
public class RestReportingEngineFacade {
	
	private Logger logger = LoggerFactory.getLogger(this.getClass());
	
	private static String NEWLINE = System.getProperty("line.separator");
	
	@Value("${APPSENSOR_REST_REPORTING_ENGINE_URL}")
	private String restReportingEngineUrl;
	
	@Value("${APPSENSOR_CLIENT_APPLICATION_ID_HEADER_NAME}")
	private String clientApplicationIdName;

	@Value("${APPSENSOR_CLIENT_APPLICATION_ID_HEADER_VALUE}")
	private String clientApplicationIdValue;
	
	private WebTarget target;
	
	final Gson gson = new Gson();
	
	public RestReportingEngineFacade() { }

	@Cacheable("events")
	public Collection<Event> findEvents(String rfc3339Timestamp) {
		GenericType<Collection<Event>> responseType = new GenericType<Collection<Event>>() {};
        
		logger.info("Making REST call to " + target.getUri().toString() + " ... with path of /api/v1.0/reports/events");
		
		Collection<Event> events = 
		        target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("events")
				.queryParam("earliest", rfc3339Timestamp)
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(responseType);
		
		//make request
		return filterEventsByClientApplications(events);
	}
	
	@Cacheable("attacks")
	public Collection<Attack> findAttacks(String rfc3339Timestamp) {
		GenericType<Collection<Attack>> responseType = new GenericType<Collection<Attack>>() {};
        
		logger.info("Making REST call to " + target.getUri().toString() + " ... with path of /api/v1.0/reports/attacks");
		
		Collection<Attack> attacks = 
		        target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("attacks")
				.queryParam("earliest", rfc3339Timestamp)
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(responseType);
		
		//make request
		return filterAttacksByClientApplications(attacks);
	}
	
	@Cacheable("responses")
	public Collection<Response> findResponses(String rfc3339Timestamp) {
		GenericType<Collection<Response>> responseType = new GenericType<Collection<Response>>() {};
        
		logger.info("Making REST call to " + target.getUri().toString() + " ... with path of /api/v1.0/reports/responses");
		
		Collection<Response> responses = 
		        target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("responses")
				.queryParam("earliest", rfc3339Timestamp)
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(responseType);
		
		//make request
		return filterResponsesByClientApplications(responses);
	}
	
	private Collection<Event> filterEventsByClientApplications(Collection<Event> original) {

		final Collection<String> associatedClientApplications = AssociatedApplicationsContext.get();
		
		return original.stream().filter(r -> associatedClientApplications.contains(r.getDetectionSystem().getDetectionSystemId())).collect(Collectors.toList());
	}
	
	private Collection<Attack> filterAttacksByClientApplications(Collection<Attack> original) {

		final Collection<String> associatedClientApplications = AssociatedApplicationsContext.get();
		
		return original.stream().filter(a -> associatedClientApplications.contains(a.getDetectionSystem().getDetectionSystemId())).collect(Collectors.toList());
	}
	
	private Collection<Response> filterResponsesByClientApplications(Collection<Response> original) {

		final Collection<String> associatedClientApplications = AssociatedApplicationsContext.get();
		
		return original.stream().filter(r -> associatedClientApplications.contains(r.getDetectionSystem().getDetectionSystemId())).collect(Collectors.toList());
	}
	
	@Cacheable("events-count")
	public int countEvents(String rfc3339Timestamp) {
		return
		        target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("events")
				.path("count")
				.queryParam("earliest", rfc3339Timestamp)
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(Integer.class);
	}
	
	@Cacheable("attacks-count")
	public int countAttacks(String rfc3339Timestamp) {
		return
		        target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("attacks")
				.path("count")
				.queryParam("earliest", rfc3339Timestamp)
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(Integer.class);
	}
	
	@Cacheable("responses-count")
	public int countResponses(String rfc3339Timestamp) {
		return 
		        target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("responses")
				.path("count")
				.queryParam("earliest", rfc3339Timestamp)
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(Integer.class);
	}
	
	@Cacheable("events-by-label-count")
	public int countEventsByLabel(String rfc3339Timestamp, String label) {
		return
		        target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("events")
				.path("count-by-label")
				.queryParam("earliest", rfc3339Timestamp)
				.queryParam("label", label)
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(Integer.class);
	}
	
	@Cacheable("attacks-by-label-count")
	public int countAttacksByLabel(String rfc3339Timestamp, String label) {
		return
		        target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("attacks")
				.path("count-by-label")
				.queryParam("earliest", rfc3339Timestamp)
				.queryParam("label", label)
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(Integer.class);
	}
	
	@Cacheable("responses-by-label-count")
	public int countResponsesByLabel(String rfc3339Timestamp, String label) {
		return 
		        target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("responses")
				.path("count-by-label")
				.queryParam("earliest", rfc3339Timestamp)
				.queryParam("label", label)
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(Integer.class);
	}
	
	@Cacheable("events-by-user-count")
	public int countEventsByUser(String rfc3339Timestamp, String username) {
		return
		        target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("events")
				.path("count-by-user")
				.queryParam("earliest", rfc3339Timestamp)
				.queryParam("username", username)
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(Integer.class);
	}
	
	@Cacheable("attacks-by-user-count")
	public int countAttacksByUser(String rfc3339Timestamp, String username) {
		return
		        target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("attacks")
				.path("count-by-user")
				.queryParam("earliest", rfc3339Timestamp)
				.queryParam("username", username)
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(Integer.class);
	}
	
	@Cacheable("responses-by-user-count")
	public int countResponsesByUser(String rfc3339Timestamp, String username) {
		return 
		        target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("responses")
				.path("count-by-user")
				.queryParam("earliest", rfc3339Timestamp)
				.queryParam("username", username)
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(Integer.class);
	}
	
	public String getServerConfiguration() {
		return target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("server-config")
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(String.class);
	}
	
	public KeyValuePair getBase64EncodedServerConfiguration() {
		return target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("server-config-base64")
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(KeyValuePair.class);
	}
	
	public Collection<String> getConfiguredDetectionPointCategories() {
		Set<String> categoriesSet = new HashSet<>();
		
		String serverConfigurationString = getServerConfiguration();
		//iterate over server config using manual json since we don't want config to try and load from disk
		JsonElement rootElement = new JsonParser().parse(serverConfigurationString);
	    JsonObject  root = rootElement.getAsJsonObject();
	    JsonArray detectionPoints = root.getAsJsonArray("detectionPoints");
	    for (JsonElement element : detectionPoints) {
	    	String category = element.getAsJsonObject().get("category").getAsString();
	    	categoriesSet.add(category);
	    }
		
		List<String> categories = new ArrayList<>(categoriesSet);
		
		Collections.sort(categories);
		
		return categories;
	}
	
	public Collection<DetectionPoint> getConfiguredDetectionPoints(String label) {
		Set<DetectionPoint> allDetectionPoints = new HashSet<>();
		
		String serverConfigurationString = getServerConfiguration();
		//iterate over server config using manual json since we don't want config to try and load from disk
		JsonElement rootElement = new JsonParser().parse(serverConfigurationString);
	    JsonObject  root = rootElement.getAsJsonObject();
	    JsonArray detectionPointArray = root.getAsJsonArray("detectionPoints");

	    for (JsonElement element : detectionPointArray) {
	    	DetectionPoint point = gson.fromJson(element, DetectionPoint.class);
	    	allDetectionPoints.add(point);
	    }
		
		return allDetectionPoints.stream().filter(d -> label.equals(d.getLabel())).collect(Collectors.toSet());
	}
	
	@PostConstruct
	private void initializeData() {
		if (restReportingEngineUrl == null || clientApplicationIdName == null || clientApplicationIdValue == null) {
			StringBuilder sb = new StringBuilder("AppSensorUI must have the appropriate configuration values enabled properly.");
			
			if (restReportingEngineUrl == null) {
				sb.append(NEWLINE).append("The setting for 'APPSENSOR_REST_REPORTING_ENGINE_URL' must be set.");
			}
			
			if (clientApplicationIdName == null) {
				sb.append(NEWLINE).append("The setting for 'APPSENSOR_CLIENT_APPLICATION_ID_HEADER_NAME' must be set.");
			}
			
			if (clientApplicationIdValue == null) {
				sb.append(NEWLINE).append("The setting for 'APPSENSOR_CLIENT_APPLICATION_ID_HEADER_VALUE' must be set.");
			}
			
			throw new IllegalStateException(sb.toString());
		}
		
		target = ClientBuilder.newClient().target(restReportingEngineUrl);
	}
}
