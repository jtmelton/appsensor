package org.owasp.appsensor.handler.impl;

import java.net.URI;
import java.util.Collection;
import java.util.GregorianCalendar;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;

import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.jersey.grizzly2.httpserver.GrizzlyHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Response;

/**
 * Test basic rest request handling. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class RestRequestHandlerTest {

	// Base URI the Grizzly HTTP server will listen on
    public static final String BASE_URI = "http://localhost:9000/myapp/";
    
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

    @After
    public void tearDown() throws Exception {
        server.stop();
    }

    /**
     * Test to see that the message "Got it!" is sent in the response.
     */
    @Test
    public void testGetIt() {
    	AppSensorServer.bootstrap();
//    	@SuppressWarnings("unchecked")
//		Collection<Response> responses = (Collection<Response>) target
    	/*javax.ws.rs.core.Response response = target
			.path("api")
			.path("v1.0")
			.path("responses")
			.queryParam("detectionSystemId", "server1")
			.queryParam("earliest", (new GregorianCalendar().getTimeInMillis()) - (1000 * 60 * 60 * 2))	//2 hrs ago
			.request()
			.get();
//			.get(Collection.class);
//    	Response response = target.path("responses")
//    			.queryParam("detectionSystemId", "server1")
//    			.queryParam("earliest", (new GregorianCalendar().getTimeInMillis()) - (1000 * 60 * 60 * 2));	//2 hrs ago 
        System.err.println("response: " + response);
        */
        
        GenericType<Collection<Response>> responseType = new GenericType<Collection<Response>>() {};
        
//        String encodedAuthzHeader = "Basic " + Base64.encodeAsString("myuser:mypass");
        
        Collection<Response> responses = target
		.path("api")
		.path("v1.0")
		.path("responses")
		.queryParam("detectionSystemId", "server1")
		.queryParam("earliest", (new GregorianCalendar().getTimeInMillis()) - (1000 * 60 * 60 * 2))	//2 hrs ago
		.request()
		.header("X-Appsensor-Client-Application-Name2",  "myclientapp")
		.get(responseType);
        
        System.err.println("responses: " + responses);
        for(Response resp : responses) {
        	System.err.println(resp.getAction() + " / " + resp.getDetectionSystemId() + " / " + resp.getTimestamp());
        }
        
//        List<Response> list = new ArrayList<Response>();
//        GenericEntity<List<Response>> entity = new GenericEntity<List<Response>>(list) {};
//        javax.ws.rs.core.Response r = Response.ok(entity).build();
        
//        Collection<Response> responses = (Collection<Response>)response.getEntity();
//        System.err.println("responses: " + responses);
        
//        HttpUrlConnector huc = (HttpUrlConnector)response.getEntity();
//        
//        System.err.println(huc.toString());
        
        
//        try {
//			Thread.sleep(30000);
//		} catch (InterruptedException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
        
//        http://localhost:9000/myapp/api/v1.0/responses?detectionSystemId=server1&earliest=1382410098068
        
        
//        Collection<Response> responses = response.readEntity(Collection.class);
//        System.err.println("entity: " + response.getEntity().getClass());
//        ConnectionFactory cf = (ConnectionFactory)response.getEntity();
//        System.err.println(cf);
        
//    	
//    	Form form = new Form().param("customer", "Bill")
//    	                      .param("product", "IPhone 5")
//    	                      .param("CC", "4444 4444 4444 4444");
//    	Response response = target.request().post(Entity.form(form));
//    	assert response.getStatus() == 200;
//    	Order order = response.readEntity(Order.class);
    }
    
    /**
     * Starts Grizzly HTTP server exposing JAX-RS resources defined in this application.
     * @return Grizzly HTTP server.
     */
    private static HttpServer startServer() {
        // create a resource config that scans for JAX-RS resources and providers
        // in com.example package
        final ResourceConfig rc = new ResourceConfig().packages("org.owasp.appsensor");

//        rc.register(MoxyJsonFeature.class);
        
        // create and start a new instance of grizzly http server
        // exposing the Jersey application at BASE_URI
        return GrizzlyHttpServerFactory.createHttpServer(URI.create(BASE_URI), rc);
    }

}
