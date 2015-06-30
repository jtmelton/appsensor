package org.owasp.appsensor.ui.websocket;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.annotation.PostConstruct;
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

import org.owasp.appsensor.reporting.WebSocketJsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.messaging.core.MessageSendingOperations;
import org.springframework.scheduling.annotation.Scheduled;

import com.google.gson.Gson;

/**
 * This is an adapter for the websocket reporting engine. It simply 
 * connects to an existing appsensor websocket reporting engine, gets all the 
 * events/attacks/responses that are sent out and then echoes those to an 
 * endpoint within the appsensor-ui application. 
 * 
 * The main reasons for this are to: 
 * 	- simplify the front-end - all connections made to the appsensor-ui codebase directly
 * 	- security - echo only the objects that the user has access to
 * 	- allow for spring-boot capability of exposing the websocket component, allowing for 
 * 		both a pure websocket implementation (over stomp) as well as a fallback by using sockjs.  
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
@ClientEndpoint
public class WebSocketReportingEngineFacade {
	
	@Value("${APPSENSOR_WEB_SOCKET_HOST_URL}")
	private String websocketHostUrl;
	
	@SuppressWarnings("unused")
	private Session localSession = null;
	
	private Logger logger = LoggerFactory.getLogger(this.getClass());
	
	private boolean webSocketInitialized = false;
	
	private Gson gson = new Gson();
	
	@Autowired
    private MessageSendingOperations<String> messagingTemplate;

	public WebSocketReportingEngineFacade() { }

	@OnOpen
	public void onOpen(Session session) {
		logger.info("Connected ... " + session.getId());
	}

	@OnMessage
	public String onMessage(String message, Session session) {
//		logger.info("saw message from session id: " + session.getId() + " --> " + message);
		WebSocketJsonObject object = gson.fromJson(message, WebSocketJsonObject.class);

		String channel = "";
		switch(object.getDataType()) {
		case "event":
			channel = "/events";
            break;
		case "attack":
			channel = "/attacks";
            break;
		case "response":
			channel = "/responses";
            break;
        default:
            throw new IllegalArgumentException("Invalid data type: " + object.getDataType());
		}
		
		this.messagingTemplate.convertAndSend(channel, object.getDataValue());
		
		return null;
	}

	@OnClose
	public void onClose(Session session, CloseReason closeReason) {
		logger.info(String.format("Session %s close because of %s", session.getId(), closeReason));
		webSocketInitialized = false;
	}

	@PostConstruct
	private void connect() {
		if (! webSocketInitialized) {
			WebSocketContainer client = ContainerProvider.getWebSocketContainer();
	
			try {
	            localSession = client.connectToServer(this, new URI(websocketHostUrl));
	            webSocketInitialized = true;
	            logger.info("Connected to websocket host [%s]", websocketHostUrl);
	        } catch (DeploymentException | URISyntaxException | IOException e) {
	        	logger.warn("Connection to websocket host [" + websocketHostUrl + "] failed.", e);
	        }
		}
	}
	
	@Scheduled(fixedDelay = 5000)
    public void reconnectIfNecessary() {
		connect();
    }
	
}