package org.owasp.appsensor.event;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.DetectionSystem;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.Threshold;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.rpc.thrift.AppSensorThriftSslServer;
import org.owasp.appsensor.storage.file.FileBasedAttackStore;
import org.owasp.appsensor.storage.file.FileBasedEventStore;
import org.owasp.appsensor.storage.file.FileBasedResponseStore;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Test basic rest request handling. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:applicationContext.xml"})
public class ThriftEventManagerTest {
	
	private static User bob = new User("bob");
	
	private static DetectionPoint detectionPoint1 = new DetectionPoint();
	
	private static Collection<String> detectionSystems1 = new ArrayList<String>();
	
	private static String detectionSystem1 = "my-sample-client";
    
    @Inject
	AppSensorServer appSensorServer;
    
	@Inject
	AppSensorClient appSensorClient;

	@Inject 
	AppSensorThriftSslServer server;
	
	@BeforeClass
	public static void doSetup() {
		detectionPoint1.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint1.setLabel("IE1");
		
		detectionSystems1.add(detectionSystem1);
	}
	
	private void deleteTestFiles() throws Exception {
		FileBasedEventStore eventStore = (FileBasedEventStore)appSensorServer.getEventStore();
		FileBasedAttackStore attackStore = (FileBasedAttackStore)appSensorServer.getAttackStore();
		FileBasedResponseStore responseStore = (FileBasedResponseStore)appSensorServer.getResponseStore();

		Files.deleteIfExists(eventStore.getPath());
		Files.deleteIfExists(attackStore.getPath());
		Files.deleteIfExists(responseStore.getPath());
	}
	
	@Test
	public void testAttackCreation() throws Exception {
//		System.err.println("trustStore env " + System.getenv("javax.net.ssl.trustStore"));
//		System.err.println("trustStorePassword env " + System.getenv("javax.net.ssl.trustStorePassword"));
//		System.err.println("keyStore env " + System.getenv("javax.net.ssl.keyStore"));
//		System.err.println("keyStorePassword env " + System.getenv("javax.net.ssl.keyStorePassword"));
//		
		deleteTestFiles();
		
		ServerConfiguration updatedConfiguration = appSensorServer.getConfiguration();
		updatedConfiguration.setDetectionPoints(loadMockedDetectionPoints());
		appSensorServer.setConfiguration(updatedConfiguration);

		Thread.sleep(2000);
		
		SearchCriteria criteria = new SearchCriteria().
				setUser(bob).
				setDetectionPoint(detectionPoint1).
				setDetectionSystemIds(detectionSystems1);
		
		assertEquals(0, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(0, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")));
		
		assertEquals(1, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(0, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("localhostme")));
		
		assertEquals(2, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(0, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("localhostme")));
		
		assertEquals(3, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(1, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("localhostme")));
		
		assertEquals(4, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(1, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("localhostme")));
		
		assertEquals(5, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(1, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("localhostme")));
		
		assertEquals(6, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(2, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("localhostme")));
		
		assertEquals(7, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(2, appSensorServer.getAttackStore().findAttacks(criteria).size());
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
	
	// hack from http://stackoverflow.com/questions/318239/how-do-i-set-environment-variables-from-java
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void setEnv() throws IOException {
		Map<String, String> newenv = new HashMap<>();
		
		Resource trustStore = new ClassPathResource("truststore.jks");
		Resource keyStore = new ClassPathResource("keystore.jks");
		
		newenv.put("javax.net.ssl.trustStore", trustStore.getFile().getAbsolutePath());
		newenv.put("javax.net.ssl.trustStorePassword", "changeit");
		newenv.put("javax.net.ssl.keyStore", keyStore.getFile().getAbsolutePath());
		newenv.put("javax.net.ssl.keyStorePassword", "changeit");
		newenv.put("javax.net.debug", "all");

		try {
			Class<?> processEnvironmentClass = Class.forName("java.lang.ProcessEnvironment");
			Field theEnvironmentField = processEnvironmentClass.getDeclaredField("theEnvironment");
			theEnvironmentField.setAccessible(true);
			Map<String, String> env = (Map<String, String>) theEnvironmentField.get(null);
			env.putAll(newenv);
			Field theCaseInsensitiveEnvironmentField = processEnvironmentClass.getDeclaredField("theCaseInsensitiveEnvironment");
			theCaseInsensitiveEnvironmentField.setAccessible(true);
			Map<String, String> cienv = (Map<String, String>) theCaseInsensitiveEnvironmentField.get(null);
			cienv.putAll(newenv);
		} catch (NoSuchFieldException e) {
			try {
				Class[] classes = Collections.class.getDeclaredClasses();
				Map<String, String> env = System.getenv();
				for (Class cl : classes) {
					if ("java.util.Collections$UnmodifiableMap".equals(cl
							.getName())) {
						Field field = cl.getDeclaredField("m");
						field.setAccessible(true);
						Object obj = field.get(env);
						Map<String, String> map = (Map<String, String>) obj;
						map.clear();
						map.putAll(newenv);
					}
				}
			} catch (Exception e2) {
				e2.printStackTrace();
			}
		} catch (Exception e1) {
			e1.printStackTrace();
		}
	}
	
    @Before
    public void setUp() throws Exception {
    	System.err.println("setting up environment");
    	setEnv();
    	
    	System.err.println("starting thrift test server");

        new Thread(new Runnable() {
            public void run() {
            	server.start();
            }
        }).start();
        // start the server
        
        //let server start
        Thread.sleep(2000);
        
        System.err.println("started thrift test server");
    }

	@After
    public void tearDown() throws Exception {
    	if(server != null) {
    		System.err.println("stopping thrift test server");
    		server.stop();
    		System.err.println("stopped thrift test server");
    	}
    }
    
}
