Block Emitter Setup
=========

The steps below describe information you'll need in addition to the standard setup guide in order to understand the block emitter implementation and get it going.

Environment Variables / Properties
----------------------------------

Note: This class requires settings to run properly. This (these) can be set as either
	__environment variables ('export my_var="some_value"') -OR- environment 
    properties ('-Dmy_var=some_value')__ set at the JVM
 * __APPSENSOR_BLOCK_STORE_URL__ - the url used to connect to the appsensor block store, e.g. "http://1.2.3.4:8090/api/v1.0/blocks"
    
