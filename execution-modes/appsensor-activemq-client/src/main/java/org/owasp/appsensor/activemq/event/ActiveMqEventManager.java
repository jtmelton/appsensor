package org.owasp.appsensor.activemq.event;

import java.lang.IllegalStateException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Named;
import javax.jms.*;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.owasp.appsensor.activemq.ActiveMqConstants;
import org.owasp.appsensor.activemq.util.ActiveMqUtils;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.ClientApplication;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.RequestHandler;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.event.EventManager;
import org.owasp.appsensor.core.util.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import com.google.gson.Gson;
/**
 * <p>This is the activemq component that handles requests on the client-side.</p>
 * 
 * <p>This class has 2 primary responsibilities</p>
 * <ul>
 *   <li>Forward {@link Event}s and {@link Attack}s from {@link ClientApplication}s to 
 * 	 the ActiveMQ exchange/queue for the server-side {@link RequestHandler} to pick them up.</li>
 *   <li>Poll the ActiveMQ exchange/queue specific to this {@link ClientApplication} and
 *   store the messages locally for access.</li>
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
 *   <li><em>APPSENSOR_CLIENT_APPLICATION_NAME</em> - the name used for this client application, e.g. "my-app"</li>
 *   <li><em>APPSENSOR_ACTIVEMQ_BROKER_URL</em> - the url to connect to, e.g. "tcp://localhost:61616"</li>
 *   <li><em>APPSENSOR_ACTIVEMQ_USERNAME</em> - the username to use when connecting, e.g. "my_user"</li>
 *   <li><em>APPSENSOR_ACTIVEMQ_PASSWORD</em> - the password to use when connecting, e.g. "my_pass"</li>
 * </ul>
 *
 * <p>Note: ActiveMQ 4.x and greater provides pluggable security through various different providers.</p>
 * <p>The most common providers are</p>
 * <ul>
 * 	 <li>JAAS for authentication</li>
 * 	 <li>a default authorization mechanism using a simple XML configuration file.</li>
 * </ul>
 * 
 * @author Michal Warzecha (mwarzechaa@gmail.com)
 * 		   Robert Przystasz (robert.przystasz@gmail.com)
 * 		   Bartosz Wygledacz (bartosz.wygledacz@gmail.com)
 * 		   Magdalena Idzik (maddie@pwnag3.net)
 */
@Named
public class ActiveMqEventManager implements EventManager, ActiveMqConstants {

	private Logger logger = LoggerFactory.getLogger(getClass());
	
	@Inject
	private Environment environment;

	private Session responseListeningSession;
	
	private final Gson gson = new Gson();
	
	private boolean initializedProperly = true;
	
	/** maintain a collection of {@link Response}s as an in-memory list */
	private static Collection<Response> responses = new CopyOnWriteArrayList<>();
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) {
		if(!initializedProperly) {
			throw new IllegalStateException(getUninitializedMessage());
		}
		
		String message = gson.toJson(event);
		
		try {
			ActiveMqUtils.sendMessage(message, Collections.singletonList(APPSENSOR_ADD_EVENT_QUEUE), environment);
		} catch (JMSException e) {
			logger.error("Failed to send add event message to output queue.", e);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		if(!initializedProperly) {
			throw new IllegalStateException(getUninitializedMessage());
		}
		
		String message = gson.toJson(attack);
		
		try {
			ActiveMqUtils.sendMessage(message, Collections.singletonList(APPSENSOR_ADD_ATTACK_QUEUE), environment);
		} catch (JMSException e) {
			logger.error("Failed to send add attack message to output queue.", e);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> getResponses(String earliest) {
		if(!initializedProperly) {
			throw new IllegalStateException(getUninitializedMessage());
		}
		
		Collection<Response> matchingResponses = new HashSet<>();
		
		for(Response response : responses) {
			DateTime earliestDateTime = DateUtils.fromString(earliest);
			DateTime responseDateTime = DateUtils.fromString(response.getTimestamp());
			
			if(earliestDateTime != null && responseDateTime != null) {
				if(earliestDateTime.isBefore(responseDateTime)) {
					matchingResponses.add(response);
				}
			}
		}
		
		return responses;
	}
	
	@PostConstruct
	public void ensureEnvironmentVariablesSet() {
		initializedProperly = isInitializedProperly();
		
		if (!initializedProperly) {
			logger.error(getUninitializedMessage());
		} else {
			startListener();
		}
	}

	private void startListener() {
		String queueName = ActiveMqUtils.buildResponseQueueName(environment.getProperty(APPSENSOR_CLIENT_APPLICATION_NAME));
		responseListeningSession = createListeningSession(queueName);
	}

	private void startExceptionListener(final Connection connection) {
		try {
			connection.setExceptionListener(new ActiveMqExceptionLister());
		} catch (JMSException e) {
			logger.error("Failed to set up an exception listener", e);
		}
	}
	
	private boolean isInitializedProperly() {
		return StringUtils.isNotBlank(environment.getProperty(ACTIVEMQ_BROKER_URL_ENV_VAR_NAME)) &&
				StringUtils.isNotBlank(environment.getProperty(ACTIVEMQ_USERNAME_ENV_VAR_NAME)) &&
				StringUtils.isNotBlank(environment.getProperty(ACTIVEMQ_PASSWORD_ENV_VAR_NAME)) &&
				StringUtils.isNotBlank(environment.getProperty(APPSENSOR_CLIENT_APPLICATION_NAME));
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
		
		if (StringUtils.isBlank(environment.getProperty(APPSENSOR_CLIENT_APPLICATION_NAME))) {
			missingVariables.add(APPSENSOR_CLIENT_APPLICATION_NAME);
		} else {
			setVariables.add(APPSENSOR_CLIENT_APPLICATION_NAME);
		}
		
		if (missingVariables.size() > 0) {
			sb.append("The following Environment variables must be set: ").append(missingVariables);
			
			if (setVariables.size() > 0) {
				sb.append(" (already set variables - ").append(setVariables).append(")");
			}
		}
		
		return sb.toString();
	}

	private Session createListeningSession(final String queueName) {
		Session session = null;
		Connection connection = null;
		try {
			connection = ActiveMqUtils.createConnection(environment);
			session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
			Destination destination = session.createQueue(queueName);

			MessageConsumer consumer = session.createConsumer(destination);
			MessageListener listener = new ResponseMessageListener(queueName);
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

	private class ResponseMessageListener implements MessageListener {

		private String queueName;

		private ResponseMessageListener(String queueName){
			this.queueName = queueName;
		}

		public void onMessage(Message message) {
			try {
				if (message instanceof TextMessage) {
					TextMessage textMessage = (TextMessage) message;

					logger.trace("Received response on queue: " + queueName);

					Response response = gson.fromJson(textMessage.getText(), Response.class);

					responses.add(response);
				}
			} catch (JMSException e) {
				logger.error("Exception during message handling occurred", e);
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
