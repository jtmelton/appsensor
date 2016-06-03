package org.owasp.appsensor.activemq.util;

import java.util.Collection;

import org.apache.activemq.ActiveMQConnectionFactory;
import org.owasp.appsensor.activemq.ActiveMqConstants;
import org.springframework.core.env.Environment;

import javax.jms.*;

public class ActiveMqUtils implements ActiveMqConstants {

	public static Connection createConnection(Environment environment) throws JMSException {
		ActiveMQConnectionFactory factory = new ActiveMQConnectionFactory();
		factory.setBrokerURL(environment.getProperty(ACTIVEMQ_BROKER_URL_ENV_VAR_NAME));
		factory.setUserName(environment.getProperty(ACTIVEMQ_USERNAME_ENV_VAR_NAME));
		factory.setPassword(environment.getProperty(ACTIVEMQ_PASSWORD_ENV_VAR_NAME));
		return factory.createConnection();
	}

	public static void sendMessage(String messageText, Collection<String> queueNames, Environment environment) throws JMSException {
		Connection connection = createConnection(environment);
		Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
		MessageProducer messageProducer = session.createProducer(null);
		connection.start();

		for(String queue : queueNames) {
			TextMessage message = session.createTextMessage();
			message.setText(messageText);
			Destination destination = session.createQueue(queue);
			messageProducer.send(destination, message);
		}

		session.close();
		connection.close();
	}

	public static String buildResponseQueueName(String clientApplicationName) {
		return APPSENSOR_GET_RESPONSES_QUEUE_PREFIX + clientApplicationName + APPSENSOR_GET_RESPONSES_QUEUE_SUFFIX;
	}
	
}
