package org.owasp.appsensor.amqp.rabbitmq.event;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.owasp.appsensor.amqp.rabbitmq.RabbitMqConstants;
import org.owasp.appsensor.amqp.rabbitmq.util.RabbitMqUtils;
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
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConsumerCancelledException;
import com.rabbitmq.client.QueueingConsumer;
import com.rabbitmq.client.ShutdownSignalException;

/**
 * <p>This is the rabbit-mq component that handles requests on the client-side.</p>
 * 
 * <p>This class has 2 primary responsibilities</p>
 * <ul>
 *   <li>Forward {@link Event}s and {@link Attack}s from {@link ClientApplication}s to 
 * 	 the RabbitMQ exchange/queue for the server-side {@link RequestHandler} to pick them up.</li>
 *   <li>Poll the RabbitMQ exchange/queue specific to this {@link ClientApplication} and 
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
 *   <li><em>APPSENSOR_RABBITMQ_HOST</em> - the host to connect to, e.g. "localhost"</li>
 *   <li><em>APPSENSOR_RABBITMQ_PORT</em> - the port to connect to, e.g. "5672"</li>
 *   <li><em>APPSENSOR_RABBITMQ_USERNAME</em> - the username to use when connecting, e.g. "my_user"</li>
 *   <li><em>APPSENSOR_RABBITMQ_PASSWORD</em> - the password to use when connecting, e.g. "my_pass"</li>
 * </ul>
 * 
 * <p>Note: The RabbitMQ implementation does NOT perform access control. Due to the asynchronous 
 * nature of the communication, authentication and access control must be performed at one/both of 
 * the network layer or the RabbitMQ server itself via configuration.</p>
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class RabbitMqEventManager implements EventManager, RabbitMqConstants {

	private Logger logger = LoggerFactory.getLogger(getClass());
	
	@Inject
	private Environment environment;
	
	private final Gson gson = new Gson();
	
	private boolean initializedProperly = true;
	
	/** maintain a collection of {@link Response}s as an in-memory list */
	private static Collection<Response> responses = new CopyOnWriteArrayList<>();
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) {
		if(! initializedProperly) {
			throw new IllegalStateException(getUninitializedMessage());
		}
		
		String message = gson.toJson(event);
		
		try {
			RabbitMqUtils.sendMessage(message, Arrays.asList(APPSENSOR_ADD_EVENT_QUEUE), environment);
		} catch (IOException e) {
			logger.error("Failed to send add event message to output queue.", e);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		if(! initializedProperly) {
			throw new IllegalStateException(getUninitializedMessage());
		}
		
		String message = gson.toJson(attack);
		
		try {
			RabbitMqUtils.sendMessage(message, Arrays.asList(APPSENSOR_ADD_ATTACK_QUEUE), environment);
		} catch (IOException e) {
			logger.error("Failed to send add attack message to output queue.", e);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> getResponses(String earliest) {
		if(! initializedProperly) {
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
		
		if (! initializedProperly) {
			logger.error(getUninitializedMessage());
		} else {
			startRabbitListeners();
		}
	}
	
	private void startRabbitListeners() {
		logger.info("Starting RabbitMQ listeners for client application response queues");
		new ListenerThread().start();
		logger.info("Completed startup of RabbitMQ listeners for client application response queues");
	}
	
	private boolean isInitializedProperly() {
		return StringUtils.isNotBlank(environment.getProperty(RABBITMQ_HOST_ENV_VAR_NAME)) &&
				StringUtils.isNotBlank(environment.getProperty(RABBITMQ_PORT_ENV_VAR_NAME)) &&
				StringUtils.isNotBlank(environment.getProperty(RABBITMQ_USERNAME_ENV_VAR_NAME)) &&
				StringUtils.isNotBlank(environment.getProperty(RABBITMQ_PASSWORD_ENV_VAR_NAME)) &&
				StringUtils.isNotBlank(environment.getProperty(APPSENSOR_CLIENT_APPLICATION_NAME));
	}
	
	private String getUninitializedMessage() {
		StringBuilder sb = new StringBuilder();
		
		Collection<String> setVariables = new ArrayList<>();
		Collection<String> missingVariables = new ArrayList<>();
		
		if (StringUtils.isBlank(environment.getProperty(RABBITMQ_HOST_ENV_VAR_NAME))) {
			missingVariables.add(RABBITMQ_HOST_ENV_VAR_NAME);
		} else {
			setVariables.add(RABBITMQ_HOST_ENV_VAR_NAME);
		}
		
		if (StringUtils.isBlank(environment.getProperty(RABBITMQ_PORT_ENV_VAR_NAME))) {
			missingVariables.add(RABBITMQ_PORT_ENV_VAR_NAME);
		} else {
			setVariables.add(RABBITMQ_PORT_ENV_VAR_NAME);
		}
		
		if (StringUtils.isBlank(environment.getProperty(RABBITMQ_USERNAME_ENV_VAR_NAME))) {
			missingVariables.add(RABBITMQ_USERNAME_ENV_VAR_NAME);
		} else {
			setVariables.add(RABBITMQ_USERNAME_ENV_VAR_NAME);
		}
		
		if (StringUtils.isBlank(environment.getProperty(RABBITMQ_PASSWORD_ENV_VAR_NAME))) {
			missingVariables.add(RABBITMQ_PASSWORD_ENV_VAR_NAME);
		} else {
			setVariables.add(RABBITMQ_PASSWORD_ENV_VAR_NAME);
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
	
	private class ListenerThread extends Thread {
		
		private String queueName = RabbitMqUtils.buildResponseQueueName(environment.getProperty(APPSENSOR_CLIENT_APPLICATION_NAME));
		
		ListenerThread() {
			super();
		}
		
		@Override
		public void run() {
			try {
				Connection connection = RabbitMqUtils.createConnection(environment);
				Channel channel = connection.createChannel();
				
				channel.exchangeDeclare(APPSENSOR_EXCHANGE_NAME, "direct");
				channel.queueDeclare(queueName, true, false, false, null);
		        channel.queueBind(queueName, APPSENSOR_EXCHANGE_NAME, queueName);
		        
				logger.debug("Waiting for messages on queue \"" + queueName + "\".");
	
				QueueingConsumer consumer = new QueueingConsumer(channel);
				channel.basicConsume(queueName, true, consumer);
	
				while (true) {
					QueueingConsumer.Delivery delivery = consumer.nextDelivery();
					delivery.getBody();
					String message = new String(delivery.getBody());
					
					logger.trace("Received response on queue: " + queueName);
					
					Response response = gson.fromJson(message, Response.class);
					
					responses.add(response);
				}
			} catch (IOException | ShutdownSignalException | ConsumerCancelledException | InterruptedException e) {
				logger.error("Failed to setup listener thread", e);
			}
		}
	}
}
