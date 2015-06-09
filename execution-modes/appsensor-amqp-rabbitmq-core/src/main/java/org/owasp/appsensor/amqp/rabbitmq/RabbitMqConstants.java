package org.owasp.appsensor.amqp.rabbitmq;

public interface RabbitMqConstants {
	
	public static final String APPSENSOR_CLIENT_APPLICATION_NAME = "APPSENSOR_CLIENT_APPLICATION_NAME";
	
	public static final String APPSENSOR_EXCHANGE_NAME = "appsensor.exchange";
	
	public static final String RABBITMQ_HOST_ENV_VAR_NAME = "APPSENSOR_RABBITMQ_HOST";
	public static final String RABBITMQ_PORT_ENV_VAR_NAME = "APPSENSOR_RABBITMQ_PORT";
	public static final String RABBITMQ_USERNAME_ENV_VAR_NAME = "APPSENSOR_RABBITMQ_USERNAME";
	public static final String RABBITMQ_PASSWORD_ENV_VAR_NAME = "APPSENSOR_RABBITMQ_PASSWORD";
	
	public static final String APPSENSOR_ADD_EVENT_QUEUE = "appsensor.add.event.queue";
	public static final String APPSENSOR_ADD_ATTACK_QUEUE = "appsensor.add.attack.queue";
	
	public static final String APPSENSOR_GET_RESPONSES_QUEUE_PREFIX = "appsensor.";
	public static final String APPSENSOR_GET_RESPONSES_QUEUE_SUFFIX = ".response.queue";
}
