package org.owasp.appsensor;

import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.appsensor.event.EventManager;
import org.owasp.appsensor.response.ResponseHandler;
import org.owasp.appsensor.response.UserManager;

/**
 * This class exposes the main interfaces expected to be available 
 * to the client application. 
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class AppSensorClient {
	
	/** accessor for {@link org.owasp.appsensor.event.EventManager} */
	private EventManager eventManager; 

	/** accessor for {@link org.owasp.appsensor.response.ResponseHandler} */
	private ResponseHandler responseHandler;
	
	/** accessor for {@link org.owasp.appsensor.response.UserManager} */
	private UserManager userManager;
	
	/** Server connection with configuration info for rest/soap connections */
	private ServerConnection serverConnection;
	
	private AppSensorClient() { }
	
	public EventManager getEventManager() {
		return eventManager;
	}

	public ResponseHandler getResponseHandler() {
		return responseHandler;
	}
	
	public UserManager getUserManager() {
		return userManager;
	}

	public ServerConnection getServerConnection() {
		return serverConnection;
	}
	
	@Inject
	public void setEventManager(EventManager eventManager) {
		this.eventManager = eventManager;
	}
	
	@Inject
	public void setResponseHandler(ResponseHandler responseHandler) {
		this.responseHandler = responseHandler;
	}

	@Inject
	public void setServerConnection(ServerConnection serverConnection) {
		this.serverConnection = serverConnection;
	}

	@Inject
	public void setUserManager(UserManager userManager) {
		this.userManager = userManager;
	}
	
	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(eventManager).
				append(responseHandler).
				append(userManager).
				append(serverConnection).
				toHashCode();
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		
		AppSensorClient other = (AppSensorClient) obj;
		
		return new EqualsBuilder().
				append(eventManager, other.getEventManager()).
				append(responseHandler, other.getResponseHandler()).
				append(userManager, other.getUserManager()).
				append(serverConnection, other.getServerConnection()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
				append("responseHandlerImplementation", responseHandler).
				append("userManagerImplementation", userManager).
				append("serverConnection", serverConnection).
			    toString();
	}
}
