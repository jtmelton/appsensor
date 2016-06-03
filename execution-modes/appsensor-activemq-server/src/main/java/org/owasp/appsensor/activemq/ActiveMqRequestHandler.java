package org.owasp.appsensor.activemq;

import java.lang.IllegalStateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Named;
import javax.jms.*;

import org.apache.commons.lang3.StringUtils;
import org.owasp.appsensor.activemq.util.ActiveMqUtils;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.RequestHandler;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.exceptions.NotAuthorizedException;
import org.owasp.appsensor.core.listener.ResponseListener;
import org.owasp.appsensor.core.storage.ResponseStore;
import org.owasp.appsensor.core.storage.ResponseStoreListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import com.google.gson.Gson;

/**
 * <p>This is the activemq component that handles requests on the server-side.</p>
 * 
 * <p>This class has 2 primary responsibilities</p>
 * <ul>
 *   <li>Read the event/attack queues that are written to by client applications and forward 
 *   those to the appropriate *stores</li>
 *   <li>Listen to the {@link ResponseStore} and write the responses back to client application
 *   specific queues</li>
 * </ul>
 * 
 * <p>The "add event" queue is called "appsensor.add.event.queue".</p>
 * <p>The "add attack" queue is called "appsensor.add.attack.queue".</p>
 * <p>The response queues are client application specific and follow the naming convention 
 *    of "appsensor." + "client application name" + ".response.queue". If a client application is 
 *    named "my-app", then the queue name would be "appsensor.my-app.response.queue"</p>
 * 
 * <p>Note: This class requires a few settings to run properly. These can be set as either
 *    environment variables ('export my_var="some_value"') or environment 
 *    properties ('-Dmy_var=some_value')</p>
 * <ul>
 *   <li><em>APPSENSOR_ACTIVEMQ_BROKER_URL</em> - the url to connect to, e.g. "tcp://localhost:61616"</li>
 *   <li><em>APPSENSOR_ACTIVEMQ_USERNAME</em> - the username to use when connecting, e.g. "my_user"</li>
 *   <li><em>APPSENSOR_ACTIVEMQ_PASSWORD</em> - the password to use when connecting, e.g. "my_pass"</li>
 * </ul>
 *
 * <p>Note: ActiveMQ 4.x and greater provides pluggable security through various different providers.</p>
 * <p>The most common providers are</p>
 * <ul>
 *   <li>JAAS for authentication</li>
 * 	 <li>a default authorization mechanism using a simple XML configuration file.</li>
 * </ul>
 * 
 * @author Michal Warzecha (mwarzechaa@gmail.com)
 * 		   Robert Przystasz (robert.przystasz@gmail.com)
 * 		   Bartosz Wygledacz (bartosz.wygledacz@gmail.com)
 * 		   Magdalena Idzik (maddie@pwnag3.net)
 */
@Named
@ResponseStoreListener
public class ActiveMqRequestHandler implements RequestHandler, ActiveMqConstants, ResponseListener {

	private Logger logger = LoggerFactory.getLogger(getClass());
	
	private boolean initializedProperly = true;

	private Session eventListeningSession;

	private Session attackListeningSession;

	private final Gson gson = new Gson();
	
	@Inject
	private AppSensorServer appSensorServer;
	
	@Inject
	private Environment environment;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) throws NotAuthorizedException {
		if(!initializedProperly) {
			throw new IllegalStateException(getUninitializedMessage());
		}
		
		appSensorServer.getEventStore().addEvent(event);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) throws NotAuthorizedException {
		if(!initializedProperly) {
			throw new IllegalStateException(getUninitializedMessage());
		}
		
		appSensorServer.getAttackStore().addAttack(attack);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> getResponses(String earliest) throws NotAuthorizedException {
		throw new UnsupportedOperationException("Not used in the activemq implementation. "
				+ "Client applications receive responses from the client-specific topic in activemq.");
	}
	
	/**
	 * This implementation of onAdd watches for responses, and immediately sends them out to the
	 * appropriate exchange/queue for routing to the necessary client application(s) 
	 */
	@Override
	public void onAdd(Response response) {
		String message = gson.toJson(response);
		
		try {
			ActiveMqUtils.sendMessage(message, buildQueueNames(response), environment);
		} catch (JMSException e) {
			logger.error("Failed to send response message to output queue.", e);
		}
	}
	
	@PostConstruct
	public void ensureEnvironmentVariablesSet() {
		initializedProperly = isInitializedProperly();
		
		if (!initializedProperly) {
			logger.error(getUninitializedMessage());
		} else {
			startListeners();
		}
	}

	private void startListeners() {
		eventListeningSession = createListeningSession(APPSENSOR_ADD_EVENT_QUEUE);
		attackListeningSession = createListeningSession(APPSENSOR_ADD_ATTACK_QUEUE);
	}
	
	private boolean isInitializedProperly() {
		return StringUtils.isNotBlank(environment.getProperty(ACTIVEMQ_BROKER_URL_ENV_VAR_NAME)) &&
				StringUtils.isNotBlank(environment.getProperty(ACTIVEMQ_USERNAME_ENV_VAR_NAME)) &&
				StringUtils.isNotBlank(environment.getProperty(ACTIVEMQ_PASSWORD_ENV_VAR_NAME));
	}
	
	private String getUninitializedMessage() {
		StringBuilder sb = new StringBuilder();
		
		Collection<String> setVariables = new ArrayList<>();
		Collection<String> missingVariables = new ArrayList<>();
		
		if (StringUtils.isBlank(environment.getProperty(ACTIVEMQ_BROKER_URL_ENV_VAR_NAME))) {
			missingVariables.add(ACTIVEMQ_BROKER_URL_ENV_VAR_NAME);
		} else {
			setVariables.add(ACTIVEMQ_BROKER_URL_ENV_VAR_NAME);
		}
		
		if (StringUtils.isBlank(environment.getProperty(ACTIVEMQ_USERNAME_ENV_VAR_NAME))) {
			missingVariables.add(ACTIVEMQ_USERNAME_ENV_VAR_NAME);
		} else {
			setVariables.add(ACTIVEMQ_USERNAME_ENV_VAR_NAME);
		}
		
		if (StringUtils.isBlank(environment.getProperty(ACTIVEMQ_PASSWORD_ENV_VAR_NAME))) {
			missingVariables.add(ACTIVEMQ_PASSWORD_ENV_VAR_NAME);
		} else {
			setVariables.add(ACTIVEMQ_PASSWORD_ENV_VAR_NAME);
		}
		
		if (missingVariables.size() > 0) {
			sb.append("The following Environment variables must be set: ").append(missingVariables);
			
			if (setVariables.size() > 0) {
				sb.append(" (already set variables - ").append(setVariables).append(")");
			}
		}
		
		return sb.toString();
	}

	private void startExceptionListener(final Connection connection) {
		try {
			connection.setExceptionListener(new ActiveMqExceptionLister());
		} catch (JMSException e) {
			logger.error("Failed to set up an exception listener", e);
		}
	}

	private Session createListeningSession(final String queueName) {
		Session session = null;
		Connection connection = null;
		try {
			connection = ActiveMqUtils.createConnection(environment);
			session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
			Destination destination = session.createQueue(queueName);

			MessageConsumer consumer = session.createConsumer(destination);
			MessageListener listener = null;
			if (APPSENSOR_ADD_EVENT_QUEUE.equals(queueName)) {
				listener = new EventMessageListener(queueName);
			} else if (APPSENSOR_ADD_ATTACK_QUEUE.equals(queueName)) {
				listener = new AttackMessageListener(queueName);
			}
			consumer.setMessageListener(listener);
			startExceptionListener(connection);
			connection.start();
			logger.debug("Waiting for messages on queue \"" + queueName + "\".");

			return session;

		} catch (JMSException e) {
			logger.error("Failed to set up a listening session", e);
			if (session != null) {
				try {
					session.close();
				} catch (JMSException e1) {
					logger.error("Exception during closing of listener session occurred", e1);
				}
			}
			if (connection != null) {
				try {
					connection.close();
				} catch (JMSException e1) {
					logger.error("Exception during closing of listener connection occurred", e1);
				}
			}
			return null;
		}
	}

	/** build the appropriate queues to send this response to based on related detection systems */
	private Collection<String> buildQueueNames(final Response response) {
		Collection<String> queueNames = new HashSet<>();

		Collection<String> detectionSystemNames = appSensorServer.getConfiguration().getRelatedDetectionSystems(response.getDetectionSystem());

		for(String detectionSystemName : detectionSystemNames) {
			queueNames.add(ActiveMqUtils.buildResponseQueueName(detectionSystemName));
		}

		return queueNames;
	}

	private class AttackMessageListener implements MessageListener {

		private String queueName;

		private AttackMessageListener(String queueName) {
			this.queueName = queueName;
		}

		@Override
		public void onMessage(Message message) {
			if (message instanceof TextMessage) {
				TextMessage textMessage = (TextMessage) message;
				logger.trace("Received attack on queue: " + queueName);

				try {
					Attack attack = gson.fromJson(textMessage.getText(), Attack.class);
					addAttack(attack);
				} catch (JMSException e) {
					logger.error("Exception during message handling occurred", e);
				}

			}
		}
	}

	private class EventMessageListener implements MessageListener {

		private String queueName;

		private EventMessageListener(String queueName) {
			this.queueName = queueName;
		}

		@Override
		public void onMessage(Message message) {
			if (message instanceof TextMessage) {
				TextMessage textMessage = (TextMessage) message;
				logger.trace("Received event on queue: " + queueName);
				try {
					Event event = gson.fromJson(textMessage.getText(), Event.class);
					addEvent(event);
				} catch (JMSException e) {
					logger.error("Exception during message handling occurred", e);
				}

			}
		}
	}

	private class ActiveMqExceptionLister implements ExceptionListener {

		@Override
		public void onException(JMSException e) {
			logger.error("Problems with connection detected. Following exception occurred", e);
		}
	}
	
}