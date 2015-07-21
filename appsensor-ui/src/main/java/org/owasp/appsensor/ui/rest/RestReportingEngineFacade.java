package org.owasp.appsensor.ui.rest;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.KeyValuePair;
import org.owasp.appsensor.core.Response;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

@Service
public class RestReportingEngineFacade {
	
	private static String NEWLINE = System.getProperty("line.separator");
	
	@Value("${APPSENSOR_REST_REPORTING_ENGINE_URL}")
	private String restReportingEngineUrl;
	
	@Value("${APPSENSOR_CLIENT_APPLICATION_ID_HEADER_NAME}")
	private String clientApplicationIdName;

	@Value("${APPSENSOR_CLIENT_APPLICATION_ID_HEADER_VALUE}")
	private String clientApplicationIdValue;
	
	private WebTarget target;
	
	public RestReportingEngineFacade() { }

	public Collection<Event> findEvents(String rfc3339Timestamp) {
		GenericType<Collection<Event>> responseType = new GenericType<Collection<Event>>() {};
        
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
		return events;
	}
	
	public Collection<Attack> findAttacks(String rfc3339Timestamp) {
		GenericType<Collection<Attack>> responseType = new GenericType<Collection<Attack>>() {};
        
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
		return attacks;
	}
	
	public Collection<Response> findResponses(String rfc3339Timestamp) {
		GenericType<Collection<Response>> responseType = new GenericType<Collection<Response>>() {};
        
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
		return responses;
	}
	
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
