AppSensor ELK Stack Integration Documentation
=========

This document outlines the mechanisms required to integrate the output of the appsensor system with the ELK (elasticsearch - logstash - kibana) stack.

Acknowledgements
--------

This work was done by Sumanth Damarla as part of the 2015 OWASP Summer of Code Sprint.

Instructions
--------

This documentation focuses on configuring ELK Stack with OWASP AppSensor for visualizing the logs which highlights the attacks performed on an application.

The dashboard UI will consists of the following data about an attack.
- Timestamp
- Logsource
- Program
- Detection Point Label
- Detection Point Category
- Type of detection (Attack/Event/Response)
- User
-Device External ID
-cn1
- cn2
- cs1

This guide covers the following topics:

- *Software prerequisites.*
- *Description of data extracted from Appsensor syslog.*
- *Intro to ELK Stack and Installing procedure.*
- *Installing Tomcat Server in Ubuntu.*
- *Building AppSensor Environment.*
- *Deploying sample app in standalone container.*
- *Deploying sample app in IDE-managed container.*
- *Configuring rsyslog file for logging syslog data in syslog file.*
- *Providing Syslog as input for Logstash.*
- *Setting up appsensor-ws-rest-server-with-websocket-boot environment.*
- *Setting up appsensor-ws-rest-client-boot-data-generator environment.*
- *Display Syslog messages.*
- *Logstash Filters used for parsing Appsensor syslogs.*
- *Building dashboard using Kibana.*

Software prerequisites:
-----------------------

This guide is based on below configuration. If using a different setup, some of these steps may differ.
*Operating System :* Ubuntu 15.04 Desktop
*Processor :* Intel Core i3 -3227U CPU @ 1.90GHz x 4
*OS Type :* 64-bit
*Disk :* 17.5GB

Description of data extracted from Appsensor syslog:
---------------------------------------------------

There are three types values determined by the "cat" field. 
1.	"event_detection" is an event.
2.	"attack_detection" is an attack.
3.	"response_creation" is a response. 
We should use these as delimiters for parsing the fields (different fields are available on each type).
For each type, Example log with description of each sub-field is given below :

*Event-Detection:*
----------------

Example Log : Jul 23 11:39:11 cheerwine CEF: 0|OWASP|appsensor|1.0|IE1|Input Validation|3|cat=event_detection deviceExternalId=localhostme suser=bob

*Sub-field description:* <br/>
➔	"Input Validation" -> this field is the detection point category (parent bucket). <br/>
➔	"IE1" -> this field is the detection point label (specific identifier). <br/>
➔	"deviceExternalId=localhostme" -> "localhostme" is the name of the client application that detected this event. <br/>
➔	"suser=bob" -> "bob" is the name of the user that triggered this event. <br/>

*Attack-Detection:*
-------------------

Example-log:  Jul 23 11:39:11 cheerwine CEF: 0|OWASP|appsensor|1.0|IE1|Input Validation|7|cat=attack_detection deviceExternalId=localhostme suser=bob cn1Label=thresholdCount cn1=3 cn2Label=intervalDuration cn2=5 cs1Label=intervalUnit cs1=minutes

*Sub-field description:* <br/>
➔	"Input Validation" -> this field is the detection point category (parent bucket) <br/>
➔	"IE1" -> this field is the detection point label (specific identifier) <br/>
➔	"deviceExternalId=localhostme" -> "localhostme" is the name of the client application that detected this event <br/>
➔	"suser=bob" -> "bob" is the name of the user that triggered this event <br/>
➔	"cn1Label=thresholdCount cn1=3" -> "3" is the number of events in the threshold that triggered this attack <br/>
➔	"cn2Label=intervalDuration cn2=5" -> "5" is the duration of time in the threshold that triggered this attack <br/>
"cs1Label=intervalUnit cs1=minutes" -> "minutes" is the unit of time in the threshold that triggered this attack.
Using the 3 fields above, this threshold would be "If a user triggers this event 3 times in 5 minutes, it is considered an attack".

*Response-Detection:*
---------------------

Example log:  <br/>
Jul 23 11:39:11 cheerwine CEF: 0|OWASP|appsensor|1.0|logout|appsensor_response|7|cat=response_creation act=logout deviceExternalId=localhostme suser=bob

*Sub-fields Description:* <br/>
➔	"act=logout" -> "logout" tells me that this activity was taken as the result of this response <br/>
➔	"deviceExternalId=localhostme" -> "localhostme" is the name of the client application that detected this event <br/>
➔	"suser=bob" -> "bob" is the name of the user that triggered this event <br/>

After parsing, the data would be appearing in the following manner. <br/>

![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot1.png)

*Intro to ELK Stack and Installing procedure:*
----------------------------------------------

*Elasticsearch:* <br/>
Elasticsearch is a RESTful distributed search engine using a NoSQL database and based on the Apache Lucene engine. Developed by the Elasticsearch company which also manages Kibana and Logstash. <br/>

*Logstash:* <br/>
Logstash is a tool used to harvest and filter logs, it’s developed in Java under Apache 2.0 license. <br/>

*Kibana:* <br/>
Kibana is a web UI allowing to search and display data stored by Logstash in Elasticsearch. <br/>

*Logstash-Forwarder:* <br/>
Logstash-forwarder (previously named Lumberjack) is one of the many log shippers compliant with Logstash.
It has the following advantages: <br/>
●	a light footprint (written in Go, no need for a Java Virtual Machine to harvest logs) <br/>
●	uses a data compression algorithm<br/>
●	uses encryption to send data over the network <br/>

*Architecture* <br/>
Here is a simple schema of the expected architecture :   <br/>

![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot2.png)

Documentation of ELK stack:
---------------------------
Elastic Search : https://www.elastic.co/guide/en/elasticsearch/guide/current/getting-started.html <br/>
Logstash : https://www.elastic.co/guide/en/logstash/current/getting-started-with-logstash.html <br/>
Kibana : https://www.elastic.co/webinars/whats-new-in-kibana-4 <br/>
Logstash-Forwarder : https://github.com/elastic/logstash-forwarder <br/>
Step by step instructions to setup ELK stack environment on Ubuntu:
DigitalOcean Blog : https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-4-on-ubuntu-14-04 <br/>

*Ports used for ELK Stack(Default):* <br/>
Port 9200: Elasticsearch <br/>
Port 5610: Kibana <br/>

*Plugins Installed:* <br/>
Marvel: Used as GUI for Elasticsearch. <br/>
Kopf: kopf is a simple web administration tool for ElasticSearch written in JavaScript + AngularJS + jQuery + Twitter bootstrap. <br/>

*Installing Tomcat Server in Ubuntu:* <br/>
DigitalOcean Guide : https://www.digitalocean.com/community/tutorials/how-to-install-apache-tomcat-7-on-ubuntu-14-04-via-apt-get <br/>

*Building AppSensor Environment:* <br/>
AppSensor is a multi-module maven project. The project requires Java version 7 or higher. Building is generally handled by the following steps<br/>

- clone the repo (or your fork)
git clone https://github.com/jtmelton/appsensor.git

-	get into appsensor directory
cd appsensor

-	install multi-module parent - one time requirement per version
mvn -N install 
or
sudo apt-get update 
sudo apt-get install maven

-	run the tests - done every time you make changes
mvn test

*Deploying Sample App in Standalone Container:* <br/>
If you'd like to deploy one of these applications to a standalone application server or servlet container, follow these simple steps:
-	Download the source code (either zip download or git clone)
-	Go into the folder containing the application you want to deploy (e.g. 'simple-dashboard')
-	Execute 'mvn package'
-	Look in the 'target' folder that gets generated and find the '.war' file
-	Deploy this WAR file into your application server / servlet container and start it up
-	You should now be able to interact with the application locally

*Deploying Sample App in IDE-managed Container:* <br/>
If you'd like to deploy one of these applications to a standalone application server or servlet container, follow these simple steps:
-	Download the source code (either zip download or git clone)
-	Import the application into your IDE (using 'import maven project' mechanism)
-	Setup an IDE managed container if you don't have one already
-	Add the application to your container
-	Startup the container
-	You should now be able to interact with the application locally

*Configuring rsyslog file for logging syslog data (UDP) in syslog file:*<br/>
-	Open a file on your system called /etc/rsyslog.conf
-	Check for a line that has 
            “modload imudp” 
            "UDPServerRun 514"
-	If the above two lines are commented, remove the comment(#) and save the file.

*Appsensor-ws-rest-server-with-websocket-boot environment:* <br/>

-	Get the latest code (either clone/fork or update your existing one) and look at the dev-2.2 branch (https://github.com/jtmelton/appsensor/tree/dev-v2.2).
-	Navigate to appsensor-ws-rest-server-with-websocket-boot (https://github.com/jtmelton/appsensor/tree/dev-v2.2/sample-apps/appsensor-ws-rest-server-with-websocket-boot)
-	Open the new terminal and execute the below command which starts running the rest server.
run 'mvn spring-boot:run -DAPPSENSOR_WEB_SOCKET_HOST_URL=ws://localhost:8085/dashboard' (run from the appsensor-ws-rest-server-with-websocket-boot directory)

After successful building of Appsensor-ws-rest-server-with-websocket-boot environment, you should the find the following data on your screen. <br/>

![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot3.png)

*Appsensor-ws-rest-client-boot-data-generator environment:* <br/>

-	Get the latest code (either clone/fork or update your existing one) and look at the dev-2.2 branch (https://github.com/jtmelton/appsensor/tree/dev-v2.2).
-	Navigate to appsensor-ws-rest-client-boot-data-generator (https://github.com/jtmelton/appsensor/tree/dev-v2.2/sample-apps/appsensor-ws-rest-client-boot-data-generator). 
-	Open the new terminal and execute the below command which starts running the data generator. run 'mvn spring-boot:run' (run from the appsensor-ws-rest-client-boot-data-generator directory)

This should start printing things to syslog that will give plenty of data to test. <br/>


After successful building of Appsensor-ws-rest-client-boot-data-generator environment, you should the find the following data on your screen.<br/>

![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot4.png)

*Display syslog messages:* <br/>
To see the syslog logs, run 'tail /var/log/syslog'. You should the find the following data on your screen. <br/>

![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot5.png)

*Logstash Filters used for parsing Appsensor syslogs:*
------------------------------------------------------

The filters involved in parsing Syslog messages are <br/>
1.	Grok Filter.<br/>
2.	KV Filter. <br/>

*Grok Filter:* <br/>
Grok is currently the best way in logstash to parse unstructured log data into something structured and queryable.
This tool is perfect for syslog logs, apache and other webserver logs, mysql logs, and in general, any log format that is generally written for humans and not computer consumption. <br/>
Logstash ships with about 120 patterns by default. <br/>
Detailed description : https://www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html <br/> 

We built a custom pattern to parse the Appsensor Syslog. I am providing the grok filter code used to parse appsensor syslog below

*Grok Filter code:* <br/>
```
grok 
{
 match => [ "message","%{SYSLOGBASE}0\|OWASP\|appsensor\|1\.0\|%{WORD:Detection_point_label}\|(?<Detection_point_Category>[^|]+)\|7\|%{GREEDYDATA:keyvalues}"]
}
``` 
*KV Filter:* <br/>
This filter helps automatically parse messages (or specific event fields) which are of the ‘foo=bar’ variety.
For example, if you have a log message which contains ‘ip=1.2.3.4 error=REFUSED’, you can parse those automatically by configuring:
```
filter {
  kv { }
}
```
The above will result in a message of “ip=1.2.3.4 error=REFUSED” having the fields: <br/>
-	ip: 1.2.3.4 <br/> 
-	error: REFUSED <br/>
This is great for postfix, iptables, and other types of logs that tend towards ‘key=value’ syntax.
Detailed description : https://www.elastic.co/guide/en/logstash/current/plugins-filters-kv.html <br/>

I am providing the KV filter code used to parse appsensor syslog below <br/>



*KV Filter code: * <br/>
```
kv {
source => "keyvalues"
	remove_field => ["keyvalues"]
    	}
```
The whole logstash file which should be imported to logstash for parsing Appsensor syslog is given below. The steps to be followed are:<br/>
-	Copy the below mentioned code into textpad and save it “.conf” extension.<br/>
-	Execute “bin/logstash -f logstash.conf” command. (This command will work only if you are in logstash directory and logstash.conf is present in the directory).<br/>

*Logstash.conf Code:* <br/>
```
input {
tcp {
 port => 5000
 type => syslog
 }
}
filter {
	grok {
  	match => [ "message","%{SYSLOGBASE}0\|OWASP\|appsensor\|1\.0\|%{WORD:Detection_point_label}\|(?<Detection_point_Category>[^|]+)\|7\|%{GREEDYDATA:keyvalues}"]
}
 
kv {
         source => "keyvalues"
        remove_field => ["keyvalues"]
    }

date {
  	match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
       }
  }
output {
  elasticsearch { host => localhost
index => "dashboard"
}
  stdout { codec => rubydebug }
}
```
Once the code is executed, open new terminal and run the following command. <br/>
Command  : telnet localhost 5000 <br/>

In that window, enter the sample syslog format data, you can see the parsed text as below. <br/>

![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot6.png)

Building Dashboards using Kibana:
----------------------------------
After logstash.conf has been imported to logstash, <br/>
1. One can search for the index name in Kibana. In this case, my index name is “dashboard”. <br/>
![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot15.png)
2. Select “timestamp” as fieldname and hit create.<br/>
![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot7.png)
3. After clicking create, a list of all the fields will be created which is shown as below.<br/>
![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot8.png)
4. Later, switch to “Discover” tab. Select the time range as per convenience on the top right column. You can find all the related fields of an log on the left of window. <br/>
![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot9.png)
5. I am selecting “@timestamp” field which in my case providing five different timings.<br/>
 ![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot10.png)
6. Hit “Visualize” option which will create a basic visualization of the timestamp field.<br/>
![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot11.png)
7. Try different visualizations and save them by hitting “save” icon on top right of the tab.<br/>
![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot12.png)
8. After saving visualizations, switch to “Dashboard” tab and click on “+” symbol which enables you to add visualizations to dashboard. Later save the dashboard by hitting “save” icon on the top right of the screen.<br/>
 ![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot13.png)
9. In this way, one can create visualizations, save them and add them to dashboards. <br/>

Below is the sample dashboard which I had create. You can choose any number of available visualizations and built own dashboards. <br/>
![Alt tag](https://github.com/jtmelton/appsensor/blob/master/integrations/elk-stack-documentation/screenshots/screenshot14.png)
Kibana supports custom dashboards too…!! <br/>
Follow this guide: http://blog.trifork.com/2014/05/20/advanced-kibana-dashboard/ <br/>



