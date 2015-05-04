Kafka Setup
=========

The steps below describe information you'll need in addition to the standard setup guide in order to understand the Kafka implementation and get it going.

Topic Naming
------------

* The "add event" topic is called __appsensor-add-event-queue__.
* The "add attack" topic is called __appsensor-add-attack-queue__.
* The response topics are client application specific and follow the naming convention 
    of "appsensor-" + "client application name" + "-response-queue". If a client application is 
    named "myapp", then the queue name would be __appsensor-myapp-response-queue__

Environment Variables / Properties
----------------------------------

Note: This class requires a few settings to run properly. These can be set as either
	__environment variables ('export my_var="some_value"') -OR- environment 
    properties ('-Dmy_var=some_value')__ set at the JVM
 * __APPSENSOR_CLIENT_APPLICATION_NAME__ - the name used for this client application, e.g. "my-app"
 * __APPSENSOR_KAFKA_CONSUMER_GROUP_ID__ - A string that uniquely identifies the group of consumer processes 
    												  to which this consumer belongs. By setting the same group id multiple processes 
    											      indicate that they are all part of the same consumer group, e.g. "my-consumer-group"
 * __APPSENSOR_KAFKA_CONSUMER_ZOOKEEPER_CONNECT__ - zookeeper connect string, e.g. "hostname1:port1,hostname2:port2,hostname3:port3"
 * __APPSENSOR_KAFKA_PRODUCER_BOOTSTRAP_SERVERS__ - A list of host/port pairs to use for establishing the initial connection to 
    															the Kafka cluster, e.g. "host1:port1,host2:port2"
 * __APPSENSOR_KAFKA_PRODUCER_PARTITION__ - _(OPTIONAL, MUST be integer if set)_ The partition to which the record should be sent, e.g. "2"
 * __APPSENSOR_KAFKA_PRODUCER_KEY__ - _(OPTIONAL)_ The key that will be included in the record, e.g. "my-special-key"
 
Settings
--------

Note: This class assumes the 'auto.create.topics.enable' setting is set to 'true', which is the default. 
If not set to true, the code will fail.

Security
---------

Note: The kafka implementation does NOT perform access control. Due to the asynchronous 
nature of the communication, authentication and access control must be performed at one/both of 
the network layer or the kafka layer (current version of kafka does not provide security)
 
