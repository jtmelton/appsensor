package org.owasp.appsensor.ui.rest;

import java.util.Collection;

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

		System.err.println("got back: " + events.size() + " from " + target.getUri() + " plus " + rfc3339Timestamp);
		
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
