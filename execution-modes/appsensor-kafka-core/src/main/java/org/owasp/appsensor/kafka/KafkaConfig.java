package org.owasp.appsensor.kafka;

/**
 * <p>This is a very simple domain object with nested builder 
 * that represents the configuration settings for kafka.</p>
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class KafkaConfig {
	
	private final String clientApplicationName;
	private final String consumerGroupId;
	private final String consumerZookeeperConnect;
	private final String producerBootstrapServers;
	private final Integer producerPartition;
	private final String producerKey;
	
	private KafkaConfig(
			String clientApplicationName,
			String consumerGroupId,
			String consumerZookeeperConnect,
			String producerBootstrapServers,
			Integer producerPartition,
			String producerKey) {
		this.clientApplicationName = clientApplicationName;
		this.consumerGroupId = consumerGroupId;
		this.consumerZookeeperConnect = consumerZookeeperConnect;
		this.producerBootstrapServers = producerBootstrapServers;
		this.producerPartition = producerPartition;
		this.producerKey = producerKey;
	}
	
	public String getClientApplicationName() {
		return clientApplicationName;
	}

	public String getConsumerGroupId() {
		return consumerGroupId;
	}

	public String getConsumerZookeeperConnect() {
		return consumerZookeeperConnect;
	}

	public String getProducerBootstrapServers() {
		return producerBootstrapServers;
	}

	public Integer getProducerPartition() {
		return producerPartition;
	}

	public String getProducerKey() {
		return producerKey;
	}

	public static class KafkaConfigBuilder {
		
		private String clientApplicationName;
		private String consumerGroupId;
		private String consumerZookeeperConnect;
		private String producerBootstrapServers;
		private Integer producerPartition;
		private String producerKey;
		
		public KafkaConfigBuilder setClientApplicationName(String clientApplicationName) {
			this.clientApplicationName = clientApplicationName;
			return this;
		}
		
		public KafkaConfigBuilder setConsumerGroupId(String consumerGroupId) {
			this.consumerGroupId = consumerGroupId;
			return this;
		}
		
		public KafkaConfigBuilder setConsumerZookeeperConnect(String consumerZookeeperConnect) {
			this.consumerZookeeperConnect = consumerZookeeperConnect;
			return this;
		}
		
		public KafkaConfigBuilder setProducerBootstrapServers(String producerBootstrapServers) {
			this.producerBootstrapServers = producerBootstrapServers;
			return this;
		}
		
		public KafkaConfigBuilder setProducerPartition(Integer producerPartition) {
			this.producerPartition = producerPartition;
			return this;
		}
		
		public KafkaConfigBuilder setProducerKey(String producerKey) {
			this.producerKey = producerKey;
			return this;
		}
		
		public KafkaConfig build() {
			return new KafkaConfig(
					clientApplicationName, 
					consumerGroupId, 
					consumerZookeeperConnect, 
					producerBootstrapServers, 
					producerPartition, 
					producerKey);
		}
		
	}

}
