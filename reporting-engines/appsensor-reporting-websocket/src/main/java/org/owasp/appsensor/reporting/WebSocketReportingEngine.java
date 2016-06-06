package org.owasp.appsensor.reporting;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;

import javax.inject.Named;
import javax.websocket.ClientEndpoint;
import javax.websocket.CloseReason;
import javax.websocket.ContainerProvider;
import javax.websocket.DeploymentException;
import javax.websocket.OnClose;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.websocket.WebSocketContainer;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.KeyValuePair;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.exceptions.NotAuthorizedException;
import org.owasp.appsensor.core.reporting.ReportingEngine;
import org.owasp.appsensor.core.storage.AttackStoreListener;
import org.owasp.appsensor.core.storage.EventStoreListener;
import org.owasp.appsensor.core.storage.ResponseStoreListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import com.google.gson.Gson;

/**
 * This is the websocket-based reporting engine, and is an implementation of the observer pattern. 
 * 
 * It is notified with implementations of the *Listener interfaces and is 
 * passed the observed objects. In this case, we are concerned with {@link Event},
 *  {@link Attack} and {@link Response}
 * implementations. 
 * 
 * The implementation simply converts the object to json and sends it out on the websocket.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Named
@EventStoreListener
@AttackStoreListener
@ResponseStoreListener
@ClientEndpoint
public class WebSocketReportingEngine implements ReportingEngine {
	
	// "ws://localhost:8080/simple-websocket-dashboard/dashboard"
	private final String APPSENSOR_WEB_SOCKET_HOST_URL_PROPERTY_NAME = "APPSENSOR_WEB_SOCKET_HOST_URL";
	
	private String websocketHostUrl;
	
	private Session localSession = null;
	
	private Logger logger = LoggerFactory.getLogger(this.getClass());
	
	private boolean webSocketInitialized = false;
	
	private Gson gson = new Gson();
	
	public WebSocketReportingEngine() { }
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Event event) {
		notifyWebSocket("event", event);
		
		logger.info("Reporter observed event by user [" + event.getUser().getUsername() + "]");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Attack attack) {
		notifyWebSocket("attack", attack);
		
		logger.info("Reporter observed attack by user [" + attack.getUser().getUsername() + "]");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Response response) {
		notifyWebSocket("response", response);
		
		logger.info("Reporter observed response for user [" + response.getUser().getUsername() + "]");
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Event> findEvents(String earliest) {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Attack> findAttacks(String earliest) {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> findResponses(String earliest) {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getServerConfigurationAsJson() throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int countEvents(String earliest) throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int countAttacks(String earliest) throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int countResponses(String earliest) throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public int countEventsByLabel(String earliest, String label) throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int countAttacksByLabel(String earliest, String label) throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int countResponsesByLabel(String earliest, String label) throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public int countEventsByUser(String earliest, String user) throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int countAttacksByUser(String earliest, String user) throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int countResponsesByUser(String earliest, String user) throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public KeyValuePair getBase64EncodedServerConfigurationFileContent() throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}
	
	private void notifyWebSocket(String type, Object object) {
		ensureConnected();
		
		if (localSession != null && localSession.isOpen()) {
			try {
				WebSocketJsonObject jsonObject = new WebSocketJsonObject(type, object);
				String json = gson.toJson(jsonObject);
				localSession.getBasicRemote().sendText(json);
			} catch (IOException e) {
				logger.error("Error sending data to websocket", e);
			}
		}
	}
	
	@OnOpen
	public void onOpen(Session session) {
		logger.info("Connected ... " + session.getId());
	}

	@OnMessage
	public void onMessage(String message, Session session) { }

	@OnClose
	public void onClose(Session session, CloseReason closeReason) {
		logger.info(String.format("Session %s close because of %s",
				session.getId(), closeReason));
	}

	private void ensureConnected() {
		if (! webSocketInitialized) {
			WebSocketContainer client = ContainerProvider.getWebSocketContainer();
	
			if (websocketHostUrl == null) {
				String systemProperty = System.getProperty(APPSENSOR_WEB_SOCKET_HOST_URL_PROPERTY_NAME);
				String osProperty = System.getenv(APPSENSOR_WEB_SOCKET_HOST_URL_PROPERTY_NAME);
				
				//prefer system property
				if (StringUtils.hasText(systemProperty)) {
					websocketHostUrl = systemProperty;
				} else if (StringUtils.hasText(osProperty)) {
					websocketHostUrl = osProperty;
				}
			}
			
			if(websocketHostUrl == null) {
				throw new IllegalStateException("WebSocket host url must be configured either through a system property or OS property.");
			}
			
			try {
				//"ws://localhost:8080/simple-websocket-dashboard/dashboard"
	            localSession = client.connectToServer(WebSocketReportingEngine.class, new URI(websocketHostUrl));
	            webSocketInitialized = true;
	        } catch (DeploymentException | URISyntaxException | IOException e) {
	            throw new RuntimeException(e);
	        }
	    	System.err.println("started and connected");
		}
	}

}