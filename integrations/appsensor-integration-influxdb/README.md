InfluxDB Setup
=========

The steps below describe information you'll need in addition to the standard setup guide in order to understand the InfluxDB implementation and get it going.

Database and Measurement Naming
------------

This implementation uses some standard configuration settings:

* The database is named "appsensor". (Note: this must exist beforehand)
* There are 3 measurements produced:
* The measurement for events is named "appsensor_events"
* The measurement for attacks is named "appsensor_attacks"
* The measurement for responses is named "appsensor_responses"

Environment Variables / Properties
----------------------------------

Note: This class requires a few settings to run properly. These can be set as either
	__environment variables ('export my_var="some_value"') -OR- environment 
    properties ('-Dmy_var=some_value')__ set at the JVM
 * __APPSENSOR_INFLUXDB_URL__ - the url used to connect to influxdb, e.g. "http://1.2.3.4:8086"
 * __APPSENSOR_INFLUXDB_USERNAME__ - the username used to connect to influxdb, e.g. "my_username"
 * __APPSENSOR_INFLUXDB_PASSWORD__ - the password used to connect to influxdb, e.g. "my_password"
    
