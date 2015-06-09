package org.owasp.appsensor.amqp.rabbitmq.util;

import java.io.IOException;
import java.util.Collection;

import org.owasp.appsensor.amqp.rabbitmq.RabbitMqConstants;
import org.springframework.core.env.Environment;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;

public class RabbitMqUtils implements RabbitMqConstants {

	public static Connection createConnection(Environment environment) throws IOException {
		ConnectionFactory factory = new ConnectionFactory();
		
		factory.setHost(environment.getProperty(RABBITMQ_HOST_ENV_VAR_NAME));
		factory.setPort(Integer.parseInt(environment.getProperty(RABBITMQ_PORT_ENV_VAR_NAME)));
		factory.setUsername(environment.getProperty(RABBITMQ_USERNAME_ENV_VAR_NAME));
		factory.setPassword(environment.getProperty(RABBITMQ_PASSWORD_ENV_VAR_NAME));
		
		Connection connection = factory.newConnection();
		
		return connection;
	}

	public static void sendMessage(String message, Collection<String> queueNames, Environment environment) throws IOException {
		Connection connection = createConnection(environment);
		Channel channel = connection.createChannel();

		channel.exchangeDeclare(APPSENSOR_EXCHANGE_NAME, "direct");
		
		for(String queueName : queueNames) {
			channel.queueDeclare(queueName, true, false, false, null);
	
			channel.basicPublish(APPSENSOR_EXCHANGE_NAME, queueName, null, message.getBytes());
		}

		channel.close();
		connection.close();
	}
	
	public static String buildResponseQueueName(String clientApplicationName) {
		return APPSENSOR_GET_RESPONSES_QUEUE_PREFIX + clientApplicationName + APPSENSOR_GET_RESPONSES_QUEUE_SUFFIX;
	}
	
}
