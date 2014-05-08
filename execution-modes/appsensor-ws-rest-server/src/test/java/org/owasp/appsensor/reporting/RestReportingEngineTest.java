package org.owasp.appsensor.reporting;

import java.net.URI;
import java.util.Collection;

import javax.inject.Inject;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;

import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.jersey.grizzly2.httpserver.GrizzlyHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.util.DateUtils;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Test basic rest request handling. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:applicationContext.xml"})
public class RestReportingEngineTest {

	// Base URI the Grizzly HTTP server will listen on
    public static final String BASE_URI = "http://localhost:9000/myapp/";
    
    @Inject 
    DemoDataMultiUserPopulator demoDataMultiUserPopulator;
    
    private HttpServer server;
    private WebTarget target;

    @Before
    public void setUp() throws Exception {
        // start the server
        server = startServer();
        // create the client
        Client restClient = ClientBuilder.newClient();

        // uncomment the following line if you want to enable
        // support for JSON in the client (you also have to uncomment
        // dependency on jersey-media-json module in pom.xml and Main.startServer())
        // --
//        restClient.register(MoxyJsonFeature.class);

        target = restClient.target(BASE_URI);
    }

    @SuppressWarnings("deprecation")
	@After
    public void tearDown() throws Exception {
        server.stop();
    }

    /**
     * Test to see that the message "Got it!" is sent in the response.
     */
    @Test
    public void testGetIt() {
    	demoDataMultiUserPopulator.generateData(0,  50);
    	
        GenericType<Collection<Response>> responseType = new GenericType<Collection<Response>>() {};
        
        DateTime twoHoursAgo = DateUtils.getCurrentTimestamp().minusHours(2);
        
        Collection<Response> responses = target
		.path("api")
		.path("v1.0")
		.path("/reports")
		.path("responses")
		.queryParam("earliest", twoHoursAgo.toString())	//2 hrs ago
		.request()
		.header("X-Appsensor-Client-Application-Name2",  "myclientapp")
		.get(responseType);
        
        System.err.println("responses: " + responses);
        for(Response resp : responses) {
        	System.err.println(resp.getAction() + " / " + resp.getDetectionSystemId() + " / " + resp.getTimestamp());
        }
    }
    
    /**
     * Starts Grizzly HTTP server exposing JAX-RS resources defined in this application.
     * @return Grizzly HTTP server.
     */
    private static HttpServer startServer() {
        // create a resource config that scans for JAX-RS resources and providers
        // in com.example package
        final ResourceConfig rc = new ResourceConfig().packages("org.owasp.appsensor");

        // create and start a new instance of grizzly http server
        // exposing the Jersey application at BASE_URI
        return GrizzlyHttpServerFactory.createHttpServer(URI.create(BASE_URI), rc);
    }

}
