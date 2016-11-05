package org.appSensor;

import org.owasp.appsensor.clientLibs.java.api.*;
import org.owasp.appsensor.clientLibs.java.model.*;
import org.owasp.appsensor.clientLibs.java.handler.*;

import java.math.BigDecimal;
import java.util.*;

import org.joda.time.DateTimeZone;
import org.joda.time.DateTime;

/**
 * AppSensor's REST Web Services demo. 
 * These sample code uses the AppSensor RestApi Java client libraries.  
 * The "clientLibs.java-1.0-jar-with-dependencies.jar" file should be accessible through the Java build path.
 * More information can be found at: client-libs/readme.md
 * 
 * @author Mahmoud Mohammadi (mahmood.mohamadi@gmail.com) 
 * 
 */


public class RestApiJavaDemo {

	public static void main(String[] args) {
		
		RestReportingEngineApi apiInstance = new RestReportingEngineApi();
		
		RestRequestHandlerApi apiHandler = new RestRequestHandlerApi();
		
		// The Appsensor's custom request header
		apiInstance.getApiClient().addDefaultHeader("X-Appsensor-Client-Application-Name2","myclientapp");
		
		//Setting the address of the server listening to the rest api requests.
		apiInstance.getApiClient().setBasePath("http://localhost:8085");
			
		
		try {

			// Getting the current web services configuration settings
			getServerConfiguration(apiInstance)	;		

			//Calling the web service to add a new event 
			addEvent(apiHandler);

			// Calling the web service to get the events 
			getEvents(apiInstance);

		} catch (ApiException e) {

			e.printStackTrace();
		}
	}

	/**
	 * @param apiInstance
	 * 
	 * @throws ApiException
	 */
	private static void getServerConfiguration(RestReportingEngineApi apiInstance) {

		String result;
		try {

			result = apiInstance.resourceRestReportingEngineGetServerConfigurationAsJsonGET();
			
			System.out.println(result + "\n");

		} catch (ApiException e) {

			e.printStackTrace();
		}
	}

	/**
	 * @param apiHandler
	 * 
	 * @throws ApiException
	 */
	private static void getEvents(RestReportingEngineApi apiInstance) throws ApiException {
		
		
		String earliest = new DateTime(DateTimeZone.UTC).toString();
		//earliest = "2016-08-02T14:00:00.05Z";
		//Getting all the events after the time set by the "earliest" parameter. 
		List<JsonEvent> events= apiInstance.resourceRestReportingEngineFindEventsGET(earliest);
		
		for (JsonEvent e : events) {
			System.out.print(e.toString() + "\n");
		}
	}
	
	/**
	 * @param apiHandler
	 * 
	 * @throws ApiException
	 */
	private static void getResponses(RestRequestHandlerApi apiHandler) throws ApiException {
		
		
		String earliest = new DateTime(DateTimeZone.UTC).toString();
		
		//Getting all the responses before the time set by the "earliest" parameter. 
		List<JsonResponse> responses =apiHandler.resourceRestRequestHandlerGetResponsesGET(earliest);
		
		for (JsonResponse resp : responses) {
			System.out.print(resp.toString() + "\n");
		}
	}

	/**
	 * @param apiHandler
	 * @throws ApiException
	 */
	private static void addEvent(RestRequestHandlerApi apiHandler)
			throws ApiException {
		
		JsonEvent event = new JsonEvent();
		
		JsonUser user = new JsonUser();	
		
		//Setting the user name related to the event
		user.setUsername("username666");
		
		JsonIpaddress ip = new JsonIpaddress();	
		
		//IP address of the source of the event
		ip.setAddress("8.8.8.8");
		
		JsonGeolocation location = new JsonGeolocation();
		location.setLatitude(new BigDecimal(37.596758));
		location.setLongitude(new BigDecimal(-121.647992));
		 
		ip.setGeoLocation(location);
		user.setIpAddress(ip);
		
		JsonDetectionsystem detectionSys = new JsonDetectionsystem();
				
		JsonDetectionpoint detectionPoint = new JsonDetectionpoint();
		detectionPoint.setCategory("Input Validation");
		detectionPoint.setLabel("IE1");
		
		event.setDetectionPoint(detectionPoint);
		event.setDetectionSystem(detectionSys);
		
		//Setting the current time as the time of the Event
		event.setTimestamp(new DateTime(DateTimeZone.UTC).toString());
		event.setUser(user);
		
		//Calling the corresponding REST API web service to add the event
		apiHandler.resourceRestRequestHandlerAddEventPOST(event);
	}
	
	/**
	 * @param apiHandler
	 * @throws ApiException
	 */
	private static void addAttack(RestRequestHandlerApi apiHandler)
			throws ApiException {
		
		JsonAttack attack = new JsonAttack();
		
		// Setting the user name related to the Attack
		JsonUser user = new JsonUser();			
		user.setUsername("username");
		
		// Setting the IP address of the attacked system
		JsonIpaddress ip = new JsonIpaddress();			
		ip.setAddress("8.8.8.8");
		
		JsonGeolocation location = new JsonGeolocation();
		location.setLatitude(new BigDecimal(37.596758));
		location.setLongitude(new BigDecimal(-121.647992));
		 
		ip.setGeoLocation(location);
		
		user.setIpAddress(ip);
		
		JsonDetectionsystem detectionSys = new JsonDetectionsystem();
		detectionSys.setDetectionSystemId("Sample System");
		
		JsonDetectionpoint detectionPoint = new JsonDetectionpoint();
		detectionPoint.setCategory("Input Validation");
		detectionPoint.setLabel("IE1");
		
		//Defining a Threshold : 5 occurrences having 20 seconds between each.
		JsonThreshold thr = new JsonThreshold();
		thr.setCount(new BigDecimal(5));
		
		JsonInterval interval = new JsonInterval();
		interval.setDuration(new BigDecimal(20));
		interval.setUnit("seconds");
		
		thr.setInterval(interval);
		
		detectionPoint.setThreshold(thr);
				
		attack.setDetectionPoint(detectionPoint);
		attack.setDetectionSystem(detectionSys);
		
		//Setting the current time as the time of the Event
		attack.setTimestamp(new DateTime(DateTimeZone.UTC).toString());
		attack.setUser(user);
		
		//Calling the corresponding REST API web service to add the Attack
		apiHandler.resourceRestRequestHandlerAddAttackPOST(attack);
		
	}
	
	
}




