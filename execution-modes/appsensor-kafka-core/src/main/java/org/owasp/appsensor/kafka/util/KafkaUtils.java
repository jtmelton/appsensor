package org.owasp.appsensor.kafka.util;

import org.owasp.appsensor.kafka.KafkaConstants;

/**
* <p>Simple utility class with helpers for kafka.</p>
* 
* @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
*/
public class KafkaUtils implements KafkaConstants {

	public static String buildResponseTopicName(String clientApplicationName) {
		return APPSENSOR_GET_RESPONSES_TOPIC_PREFIX + clientApplicationName + APPSENSOR_GET_RESPONSES_TOPIC_SUFFIX;
	}
	
}
