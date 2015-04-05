package org.owasp.appsensor.kafka;

/**
 * <p>Constants for KAFKA.</p>
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface KafkaConstants {
	
	public static final String APPSENSOR_CLIENT_APPLICATION_NAME = "APPSENSOR_CLIENT_APPLICATION_NAME";
	
	public static final String KAFKA_CONSUMER_GROUP_ID = "APPSENSOR_KAFKA_CONSUMER_GROUP_ID";
	public static final String KAFKA_CONSUMER_ZOOKEEPER_CONNECT = "APPSENSOR_KAFKA_CONSUMER_ZOOKEEPER_CONNECT";
	
	public static final String KAFKA_PRODUCER_BOOTSTRAP_SERVERS = "APPSENSOR_KAFKA_PRODUCER_BOOTSTRAP_SERVERS";
	public static final String KAFKA_PRODUCER_PARTITION = "APPSENSOR_KAFKA_PRODUCER_PARTITION";	//optional, must be integer if exists ... only considered if key exists
	public static final String KAFKA_PRODUCER_KEY = "APPSENSOR_KAFKA_PRODUCER_KEY";	//optional
	
	public static final String APPSENSOR_ADD_EVENT_TOPIC = "appsensor-add-event-topic";
	public static final String APPSENSOR_ADD_ATTACK_TOPIC = "appsensor-add-attack-topic";
	
	public static final String APPSENSOR_GET_RESPONSES_TOPIC_PREFIX = "appsensor-";
	public static final String APPSENSOR_GET_RESPONSES_TOPIC_SUFFIX = "-response-topic";
	
	public static final String EVENT_TYPE = "EVENT";
	public static final String ATTACK_TYPE = "ATTACK";
	public static final String RESPONSE_TYPE = "RESPONSE";

}