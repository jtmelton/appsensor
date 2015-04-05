package org.owasp.appsensor.kafka.util;

import java.util.Collection;
import java.util.Properties;
import java.util.concurrent.ExecutionException;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;
import org.owasp.appsensor.kafka.KafkaConfig;

/**
 * <p>This is a helper class that handles kafka producer interactions
 * such as producing records and sending them.</p>
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class KafkaSender {

	private final KafkaConfig config;
	
	private static KafkaProducer<String, String> producer;
	
	public KafkaSender(KafkaConfig config) {
		this.config = config;
		initializeProducer();
	}
	
	public void send(Collection<String> topics, String message) throws InterruptedException, ExecutionException {
		for(String topic : topics) {
			ProducerRecord<String, String> record = null;
			
			// 3 different modes
			if (config.getProducerPartition() != null && config.getProducerKey() != null) {
				
				// #1. partition AND key
				record = new ProducerRecord<String, String>(topic, config.getProducerPartition(), config.getProducerKey(), message);
			} else if (config.getProducerKey() != null) {
				
				// #2. key only
				record = new ProducerRecord<String, String>(topic, config.getProducerKey(), message);
			} else {
				
				// #3. neither partition or key
				record = new ProducerRecord<String, String>(topic, message);
			}
			
			producer.send(record).get();
		}
	}
	
	private void initializeProducer() {
		Properties props = new Properties();

		props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,config.getProducerBootstrapServers());
		props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
		props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
		props.put(ProducerConfig.ACKS_CONFIG, "1");	//set statically
		props.put(ProducerConfig.CLIENT_ID_CONFIG, config.getClientApplicationName());
		
		producer = new KafkaProducer<String, String>(props);
	}
	
}
