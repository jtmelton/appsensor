package org.owasp.appsensor.websocket;

import java.io.IOException;

import javax.websocket.OnClose;
import javax.websocket.OnError;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

/**
 * A simple dashboard for the websocket implementation.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@ServerEndpoint(value = "/dashboard")
public class Dashboard {
    
    @OnOpen
    public void onOpen(final Session session) {
    	System.err.println("Opened connection with client: " + session.getId());
    }
    
    @OnMessage
    public String onMessage(String message, Session session) {
    	System.err.println("New message from Client " + session.getId() + ": " + message);
    	
    	//should echo back whatever is heard from any client to all clients
    	for (Session sess : session.getOpenSessions()) {
    		if (sess.isOpen()) {
    			try {
					sess.getBasicRemote().sendText(message);
				} catch (IOException e) {
					e.printStackTrace();
				}
    		}
    	}

    	return null;
    }
    
    @OnClose
    public void onClose(Session session) {
    	System.err.println("Closed connection with client: " + session.getId());
    }
    
    @OnError
    public void onError(Throwable exception, Session session) {
    	System.err.println("Error for client: " + session.getId());
    }
}