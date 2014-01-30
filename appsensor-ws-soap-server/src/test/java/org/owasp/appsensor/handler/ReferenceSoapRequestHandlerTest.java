package org.owasp.appsensor.handler;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Endpoint;
import javax.xml.ws.Service;
import javax.xml.ws.handler.Handler;

import org.junit.Test;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.User;
import org.owasp.appsensor.event.StatisticalEvent;
import org.owasp.appsensor.handler.ReferenceSoapRequestHandler;
import org.owasp.appsensor.handler.RegisterClientApplicationIdentificationHandler;
import org.owasp.appsensor.handler.SoapRequestHandler;

/**
 * Test basic soap event handling. Add a number of events matching 
 * the known set of criteria and ensure the attacks are triggered at 
 * the appropriate points and that the expected responses are returned 
 * from the soap handler
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ReferenceSoapRequestHandlerTest {
	
	private static User bob = new User("bob");
	
	private static DetectionPoint detectionPoint1 = new DetectionPoint("IE1");
	
	private static String SERVICE_URL = "http://localhost:8080/appsensor/services/SoapRequestHandler";
	
    @SuppressWarnings("rawtypes")
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
        
        // HandlerChain installation
        Binding binding = ((BindingProvider) requestHandler).getBinding();
        List<Handler> handlerChain = binding.getHandlerChain();
        if (handlerChain == null) {
        	handlerChain = new ArrayList<Handler>();
        }
        handlerChain.add(new RegisterClientApplicationIdentificationHandler());
        binding.setHandlerChain(handlerChain);
        
        long startMillis = new Date().getTime() - 1000;	//current time - 1 second - account for clock drift
        
        assertEquals(0, requestHandler.getResponses(startMillis).size());
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
        
        assertEquals(0, requestHandler.getResponses(startMillis).size());
        //this is 11th
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        assertEquals(1, requestHandler.getResponses(startMillis).size());
        
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
        
        assertEquals(1, requestHandler.getResponses(startMillis).size());
        //this is 22nd
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        assertEquals(2, requestHandler.getResponses(startMillis).size());
        
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        requestHandler.addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
        
        assertEquals(2, requestHandler.getResponses(startMillis).size());
        
        endpoint.stop();
        System.err.println("Stopped service");
    }
}


