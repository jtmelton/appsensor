package org.owasp.appsensor.handler.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.net.URL;
import java.util.Date;

import javax.xml.namespace.QName;
import javax.xml.ws.Endpoint;
import javax.xml.ws.Service;

import org.junit.Test;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.StatisticalEvent;
import org.owasp.appsensor.User;
import org.owasp.appsensor.handler.SoapRequestHandler;


public class ReferenceSoapRequestHandlerTest {
	
	private static User bob = new User("bob", "1.2.3.4");
	
	private static DetectionPoint detectionPoint1 = new DetectionPoint("IE1");
	
	private static String detectionSystem1 = "localhostme";
	
	private static String SERVICE_URL = "http://localhost:8080/appsensor/services/SoapRequestHandler";
    @Test
    public void test() throws Exception {
		System.err.println("Starting service");
		AppSensorServer.bootstrap();
    	Endpoint endpoint = Endpoint.publish(SERVICE_URL, new ReferenceSoapRequestHandler());
		
        Service soapHandlerService = Service.create(
                new URL(SERVICE_URL + "?wsdl"),
                new QName("https://www.owasp.org/index.php/OWASP_AppSensor_Project/wsdl", "SoapRequestHandlerService"));

        assertNotNull(soapHandlerService);

        SoapRequestHandler requestHandler = soapHandlerService.getPort(SoapRequestHandler.class);
        
        long startMillis = new Date().getTime() - 1000;	//current time - 1 second - account for clock drift
        
        assertEquals(0, requestHandler.getResponses(detectionSystem1, startMillis).size());
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        
        assertEquals(0, requestHandler.getResponses(detectionSystem1, startMillis).size());
        //this is 11th
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        assertEquals(1, requestHandler.getResponses(detectionSystem1, startMillis).size());
        
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        
        assertEquals(1, requestHandler.getResponses(detectionSystem1, startMillis).size());
        //this is 22nd
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        assertEquals(2, requestHandler.getResponses(detectionSystem1, startMillis).size());
        
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        
        assertEquals(2, requestHandler.getResponses(detectionSystem1, startMillis).size());
        
        endpoint.stop();
        System.err.println("Stopped service");
    }
}


