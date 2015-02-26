package org.owasp.appsensor.reporting;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;

import javax.annotation.PostConstruct;
import javax.inject.Named;
import javax.websocket.ClientEndpoint;
import javax.websocket.CloseReason;
import javax.websocket.DeploymentException;
import javax.websocket.OnClose;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;

import org.glassfish.tyrus.client.ClientManager;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.reporting.ReportingEngine;
import org.owasp.appsensor.core.storage.AttackStoreListener;
import org.owasp.appsensor.core.storage.EventStoreListener;
import org.owasp.appsensor.core.storage.ResponseStoreListener;
import org.slf4j.Logger;

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
@Loggable
@EventStoreListener
@AttackStoreListener
@ResponseStoreListener
@ClientEndpoint
public class WebSocketReportingEngine implements ReportingEngine {
	
	private Session localSession = null;
	
	private Logger logger;
	
	private boolean webSocketInitialized = false;
	
	private Gson gson = new Gson();
	
	public WebSocketReportingEngine() { }
	
	@PostConstruct
	public void attemptInitialConnection() {
		ensureConnected();
	}
	
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
		if(logger != null) {
			logger.info("Connected ... " + (session != null ? session.getId() : ""));
		} else {
			System.err.println("Connected ... " + (session != null ? session.getId() : ""));
		}
	}

	@OnMessage
	public String onMessage(String message, Session session) {
		return null;
	}

	@OnClose
	public void onClose(Session session, CloseReason closeReason) {
		if(logger != null) {
			logger.info(String.format("Session closed because of %s", closeReason));
		} else {
			System.err.println(String.format("Session closed because of %s", closeReason));
		}
	}

	private void ensureConnected() {
		if (! webSocketInitialized) {
//			WebSocketContainer client = ContainerProvider.getWebSocketContainer();
			ClientManager client = ClientManager.createClient();

			try {
	            localSession = client.connectToServer(WebSocketReportingEngine.class, new URI("ws://localhost:8080/simple-websocket-dashboard/dashboard"));
	            webSocketInitialized = true;
	        } catch (DeploymentException | URISyntaxException | IOException e) {
	        	System.err.println("Bailing out");
	            throw new RuntimeException(e);
	        }
	    	System.err.println("started and connected");
		}
	}
	
}
