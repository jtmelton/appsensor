package org.owasp.appsensor.event;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.net.URL;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.inject.Inject;
import javax.xml.namespace.QName;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Service;
import javax.xml.ws.handler.Handler;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.Threshold;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.handler.RegisterClientApplicationIdentificationHandler;
import org.owasp.appsensor.handler.SoapRequestHandler;
import org.owasp.appsensor.storage.file.FileBasedAttackStore;
import org.owasp.appsensor.storage.file.FileBasedEventStore;
import org.owasp.appsensor.storage.file.FileBasedResponseStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Test basic soap event handling. Add a number of events matching 
 * the known set of criteria and ensure the attacks are triggered at 
 * the appropriate points and that the expected responses are returned 
 * from the soap handler
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:applicationContext.xml"})
public class SoapEventManagerTest {

	@Autowired
	private AppSensorClient appSensorClient;
	
	@Inject
	AppSensorServer appSensorServer;
	
	private static User bob = new User("bob");
	
	private static DetectionPoint detectionPoint1 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1");
	
//	private static Collection<String> detectionSystems1 = new ArrayList<String>();
//	
//	private static String detectionSystem1 = "my-sample-client";
	

	//appsensor/services/
	private static String SERVICE_URL = "http://localhost:8080/SoapRequestHandlerService";
	
	@BeforeClass
	public static void doSetup() throws Exception {
//		detectionPoint1.setLabel("IE1");
//		
//		detectionSystems1.add(detectionSystem1);
	}
	
	@SuppressWarnings("rawtypes")
	@Test
	public void testAttackCreation() throws Exception {
		deleteTestFiles();
		
		ServerConfiguration updatedConfiguration = appSensorServer.getConfiguration();
		updatedConfiguration.setDetectionPoints(loadMockedDetectionPoints());
		appSensorServer.setConfiguration(updatedConfiguration);
		
		System.err.println("Starting service");

		Service soapHandlerService = Service.create(
                new URL(SERVICE_URL + "?wsdl"),
                new QName("https://www.owasp.org/index.php/OWASP_AppSensor_Project/wsdl", "SoapRequestHandlerService"));

        assertNotNull(soapHandlerService);

        SoapRequestHandler requestHandler = soapHandlerService.getPort(SoapRequestHandler.class);
        
        // HandlerChain installation
        Binding binding = ((BindingProvider) requestHandler).getBinding();
        List<Handler> handlerChain = binding.getHandlerChain();
        if (handlerChain == null) {
        	handlerChain = new ArrayList<Handler>();
        }
        
        RegisterClientApplicationIdentificationHandler handler = 
        		new RegisterClientApplicationIdentificationHandler();
        handler.setAppSensorClient(appSensorClient);

        handlerChain.add(handler);
        binding.setHandlerChain(handlerChain);
        
//		try {
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "my-sample-client"));
			assertEquals(0, appSensorClient.getEventManager().getResponses().size());
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "my-sample-client"));
			assertEquals(0, appSensorClient.getEventManager().getResponses().size());
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "my-sample-client"));
			assertEquals(1, appSensorClient.getEventManager().getResponses().size());
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "my-sample-client"));
			assertEquals(1, appSensorClient.getEventManager().getResponses().size());
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "my-sample-client"));
			assertEquals(1, appSensorClient.getEventManager().getResponses().size());
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "my-sample-client"));
			assertEquals(2, appSensorClient.getEventManager().getResponses().size());
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "my-sample-client"));
			assertEquals(2, appSensorClient.getEventManager().getResponses().size());
//		} catch(WebServiceException wse) {
//			//this is ok, server may not be setup
//		}
		
		System.err.println("Stopped service");
	}
	
	private void deleteTestFiles() throws Exception {
		FileBasedEventStore eventStore = (FileBasedEventStore)appSensorServer.getEventStore();
		FileBasedAttackStore attackStore = (FileBasedAttackStore)appSensorServer.getAttackStore();
		FileBasedResponseStore responseStore = (FileBasedResponseStore)appSensorServer.getResponseStore();

		Files.deleteIfExists(eventStore.getPath());
		Files.deleteIfExists(attackStore.getPath());
		Files.deleteIfExists(responseStore.getPath());
	}
	
	private Collection<DetectionPoint> loadMockedDetectionPoints() {
		final Collection<DetectionPoint> configuredDetectionPoints = new ArrayList<DetectionPoint>();

		Interval minutes5 = new Interval(5, Interval.MINUTES);
		Interval minutes6 = new Interval(6, Interval.MINUTES);
		Interval minutes7 = new Interval(7, Interval.MINUTES);
		Interval minutes8 = new Interval(8, Interval.MINUTES);
		Interval minutes11 = new Interval(11, Interval.MINUTES);
		Interval minutes12 = new Interval(12, Interval.MINUTES);
		Interval minutes13 = new Interval(13, Interval.MINUTES);
		Interval minutes14 = new Interval(14, Interval.MINUTES);
		Interval minutes15 = new Interval(15, Interval.MINUTES);
		Interval minutes31 = new Interval(31, Interval.MINUTES);
		Interval minutes32 = new Interval(32, Interval.MINUTES);
		Interval minutes33 = new Interval(33, Interval.MINUTES);
		Interval minutes34 = new Interval(34, Interval.MINUTES);
		Interval minutes35 = new Interval(35, Interval.MINUTES);
		
		Threshold events3minutes5 = new Threshold(3, minutes5);
		Threshold events12minutes5 = new Threshold(12, minutes5);
		Threshold events13minutes6 = new Threshold(13, minutes6);
		Threshold events14minutes7 = new Threshold(14, minutes7);
		Threshold events15minutes8 = new Threshold(15, minutes8);
		
		Response log = new Response();
		log.setAction("log");
		
		Response logout = new Response();
		logout.setAction("logout");
		
		Response disableUser = new Response();
		disableUser.setAction("disableUser");
		
		Response disableComponentForSpecificUser31 = new Response();
		disableComponentForSpecificUser31.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser31.setInterval(minutes31);
		
		Response disableComponentForSpecificUser32 = new Response();
		disableComponentForSpecificUser32.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser32.setInterval(minutes32);
		
		Response disableComponentForSpecificUser33 = new Response();
		disableComponentForSpecificUser33.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser33.setInterval(minutes33);
		
		Response disableComponentForSpecificUser34 = new Response();
		disableComponentForSpecificUser34.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser34.setInterval(minutes34);
		
		Response disableComponentForSpecificUser35 = new Response();
		disableComponentForSpecificUser35.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser35.setInterval(minutes35);
		
		Response disableComponentForAllUsers11 = new Response();
		disableComponentForAllUsers11.setAction("disableComponentForAllUsers");
		disableComponentForAllUsers11.setInterval(minutes11);
		
		Response disableComponentForAllUsers12 = new Response();
		disableComponentForAllUsers12.setAction("disableComponentForAllUsers");
		disableComponentForAllUsers12.setInterval(minutes12);
		
		Response disableComponentForAllUsers13 = new Response();
		disableComponentForAllUsers13.setAction("disableComponentForAllUsers");
		disableComponentForAllUsers13.setInterval(minutes13);
		
		Response disableComponentForAllUsers14 = new Response();
		disableComponentForAllUsers14.setAction("disableComponentForAllUsers");
		disableComponentForAllUsers14.setInterval(minutes14);
		
		Response disableComponentForAllUsers15 = new Response();
		disableComponentForAllUsers15.setAction("disableComponentForAllUsers");
		disableComponentForAllUsers15.setInterval(minutes15);
		
		Collection<Response> point1Responses = new ArrayList<Response>();
		point1Responses.add(log);
		point1Responses.add(logout);
		point1Responses.add(disableUser);
		point1Responses.add(disableComponentForSpecificUser31);
		point1Responses.add(disableComponentForAllUsers11);
		
		DetectionPoint point1 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", events3minutes5, point1Responses);
		
		Collection<Response> point2Responses = new ArrayList<Response>();
		point2Responses.add(log);
		point2Responses.add(logout);
		point2Responses.add(disableUser);
		point2Responses.add(disableComponentForSpecificUser32);
		point2Responses.add(disableComponentForAllUsers12);
		
		DetectionPoint point2 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE2", events12minutes5, point2Responses);
		
		Collection<Response> point3Responses = new ArrayList<Response>();
		point3Responses.add(log);
		point3Responses.add(logout);
		point3Responses.add(disableUser);
		point3Responses.add(disableComponentForSpecificUser33);
		point3Responses.add(disableComponentForAllUsers13);
		
		DetectionPoint point3 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE3", events13minutes6, point3Responses);
		
		Collection<Response> point4Responses = new ArrayList<Response>();
		point4Responses.add(log);
		point4Responses.add(logout);
		point4Responses.add(disableUser);
		point4Responses.add(disableComponentForSpecificUser34);
		point4Responses.add(disableComponentForAllUsers14);
		
		DetectionPoint point4 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE4", events14minutes7, point4Responses);
		
		Collection<Response> point5Responses = new ArrayList<Response>();
		point5Responses.add(log);
		point5Responses.add(logout);
		point5Responses.add(disableUser);
		point5Responses.add(disableComponentForSpecificUser35);
		point5Responses.add(disableComponentForAllUsers15);
		
		DetectionPoint point5 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE5", events15minutes8, point5Responses);
		
		configuredDetectionPoints.add(point1);
		configuredDetectionPoints.add(point2);
		configuredDetectionPoints.add(point3);
		configuredDetectionPoints.add(point4);
		configuredDetectionPoints.add(point5);

		return configuredDetectionPoints;
	}
	
}