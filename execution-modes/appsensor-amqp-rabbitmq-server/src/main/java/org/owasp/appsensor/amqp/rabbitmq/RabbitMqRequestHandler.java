package org.owasp.appsensor.amqp.rabbitmq;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.lang3.StringUtils;
import org.owasp.appsensor.amqp.rabbitmq.util.RabbitMqUtils;
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
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConsumerCancelledException;
import com.rabbitmq.client.QueueingConsumer;
import com.rabbitmq.client.ShutdownSignalException;

/**
 * <p>This is the rabbit-mq component that handles requests on the server-side.</p>
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
@ResponseStoreListener
public class RabbitMqRequestHandler implements RequestHandler, RabbitMqConstants, ResponseListener {

	private Logger logger = LoggerFactory.getLogger(getClass());
	
	private boolean initializedProperly = true;
	
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
		if(! initializedProperly) {
			throw new IllegalStateException(getUninitializedMessage());
		}
		
		appSensorServer.getEventStore().addEvent(event);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) throws NotAuthorizedException {
		if(! initializedProperly) {
			throw new IllegalStateException(getUninitializedMessage());
		}
		
		appSensorServer.getAttackStore().addAttack(attack);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> getResponses(String earliest) throws NotAuthorizedException {
		throw new UnsupportedOperationException("Not used in the rabbitmq implementation. "
				+ "Client applications receive responses from the client-specific topic in rabbitmq.");
	}
	
	/**
	 * This implementation of onAdd watches for responses, and immediately sends them out to the 
	 * appropriate exchange/queue for routing to the necessary client application(s) 
	 */
	@Override
	public void onAdd(Response response) {
		String message = gson.toJson(response);
		
		try {
			RabbitMqUtils.sendMessage(message, buildQueueNames(response), environment);
		} catch (IOException e) {
			logger.error("Failed to send response message to output queue.", e);
		}
	}
	
	public Environment getEnvironment() {
		return environment;
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
		logger.info("Starting RabbitMQ listeners for event/attack queues");
		new ListenerThread(APPSENSOR_ADD_EVENT_QUEUE).start();
		new ListenerThread(APPSENSOR_ADD_ATTACK_QUEUE).start();
		logger.info("Completed startup of RabbitMQ listeners for event/attack queues");
	}
	
	private boolean isInitializedProperly() {
		return StringUtils.isNotBlank(environment.getProperty(RABBITMQ_HOST_ENV_VAR_NAME)) &&
				StringUtils.isNotBlank(environment.getProperty(RABBITMQ_PORT_ENV_VAR_NAME)) &&
				StringUtils.isNotBlank(environment.getProperty(RABBITMQ_USERNAME_ENV_VAR_NAME)) &&
				StringUtils.isNotBlank(environment.getProperty(RABBITMQ_PASSWORD_ENV_VAR_NAME));
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
		
		if (missingVariables.size() > 0) {
			sb.append("The following Environment variables must be set: ").append(missingVariables);
			
			if (setVariables.size() > 0) {
				sb.append(" (already set variables - ").append(setVariables).append(")");
			}
		}
		
		return sb.toString();
	}
	
	private class ListenerThread extends Thread {
		
		private String queueName;
		
		ListenerThread(String queueName) {
			super();
			this.queueName = queueName;
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
					
					if (APPSENSOR_ADD_EVENT_QUEUE.equals(queueName)) {
						logger.trace("Received event on queue: " + queueName);
						
						Event event = gson.fromJson(message, Event.class);
						
						addEvent(event);
					} else if (APPSENSOR_ADD_ATTACK_QUEUE.equals(queueName)) {
						logger.trace("Received attack on queue: " + queueName);
						
						Attack attack = gson.fromJson(message, Attack.class);
						
						addAttack(attack);
					} else {
						logger.trace("Received message for UNKNOWN queue: " + queueName);
					}
					
				}
			} catch (IOException | ShutdownSignalException | ConsumerCancelledException | InterruptedException e) {
				logger.error("Failed to setup listener thread", e);
			}
		}
	}
	
	/** build the appropriate queues to send this response to based on related detection systems */
	private Collection<String> buildQueueNames(Response response) {
		Collection<String> queueNames = new HashSet<>();
		
		Collection<String> detectionSystemNames = appSensorServer.getConfiguration().getRelatedDetectionSystems(response.getDetectionSystem());
		
		for(String detectionSystemName : detectionSystemNames) {
			queueNames.add(RabbitMqUtils.buildResponseQueueName(detectionSystemName));
		}

		return queueNames;
	}
	
}