AppSensor InfluxDB Grafana Integration Documentation
=========

This document outlines the mechanisms required to integrate the output of the appsensor system with InfluxDB, using Grafana as a dashboard system.

Acknowledgements
--------

This work was done by Sumanth Damarla as part of the 2015 OWASP Summer of Code Sprint.

Instructions
--------

# Overview
This documentation focuses on configuring Time-series database “Influxdb” and Grafana, An open source, feature rich metrics dashboard and graph editor with OWASP AppSensor for visualizing the logs which highlights the attacks performed on an application.

The dashboard UI will consists of the following data about an attack.
- Timestamp
- Logsource
- Program
- Detection Point Label
- Detection Point Category
- Type of detection (Attack/Event/Response)
- User
- Device External ID
- cn1
- cn2
- cs1

This guide covers the following topics:
- *Software prerequisites.*
- *Description of data extracted from Appsensor syslog.*
- *Intro to Time-series databases.*
- *Installing to Influxdb database.*
- *Getting started with Influxdb-java.*
- *Installing Grafana.*
- *Building dashboard using Grafana*

##### Software prerequisites:
This guide is based on below configuration. If using a different setup, some of these steps may differ.
- Operating System : Ubuntu 15.04 Desktop
- Processor : Intel Core i3 -3227U CPU @ 1.90GHz x 4
- OS Type : 64-bit
- Disk : 17.5GB

##### Description of data extracted from Appsensor syslog:
There are three types values determined by the "cat" field. 
1. "event_detection" is an event.
2. "attack_detection" is an attack.
3. "response_creation" is a response. 

We should use these as delimiters for parsing the fields (different fields are available on each type).
For each type, Example log with description of each sub-field is given below :

##### Event-Detection:
Example Log : 
```sh 
Jul 23 11:39:11 cheerwine CEF: 0|OWASP|appsensor|1.0|IE1|Input Validation|3|cat=event_detection deviceExternalId=localhostme suser=bob 
```
##### Sub-field description:
"Input Validation" -> this field is the detection point category (parent bucket).

"IE1" -> this field is the detection point label (specific identifier).

"deviceExternalId=localhostme" -> "localhostme" is the name of the client application that detected this event.

"suser=bob" -> "bob" is the name of the user that triggered this event.

##### Attack-Detection:
Example-log:  
```sh
Jul 23 11:39:11 cheerwine CEF: 0|OWASP|appsensor|1.0|IE1|Input Validation|7|cat=attack_detection deviceExternalId=localhostme suser=bob cn1Label=thresholdCount cn1=3 cn2Label=intervalDuration cn2=5 cs1Label=intervalUnit cs1=minutes
```
##### Sub-field description:
"Input Validation" -> this field is the detection point category (parent bucket)

"IE1" -> this field is the detection point label (specific identifier)

"deviceExternalId=localhostme" -> "localhostme" is the name of the client application that detected this event

"suser=bob" -> "bob" is the name of the user that triggered this event

"cn1Label=thresholdCount cn1=3" -> "3" is the number of events in the threshold that triggered this attack

"cn2Label=intervalDuration cn2=5" -> "5" is the duration of time in the threshold that triggered this attack

"cs1Label=intervalUnit cs1=minutes" -> "minutes" is the unit of time in the threshold that triggered this attack.

Using the 3 fields above, this threshold would be "If a user triggers this event 3 times in 5 minutes, it is considered an attack".

##### Response-Detection:
Example log: 
```sh
Jul 23 11:39:11 cheerwine CEF: 0|OWASP|appsensor|1.0|logout|appsensor_response|7|cat=response_creation act=logout deviceExternalId=localhostme suser=bob
```
##### Sub-fields Description:
"act=logout" -> "logout" tells me that this activity was taken as the result of this response.

"deviceExternalId=localhostme" -> "localhostme" is the name of the client application that detected this event.

"suser=bob" -> "bob" is the name of the user that triggered this event.

#### Intro to Time-series databases:
A time series database (TSDB) is a software system that is optimized for handling time series data, arrays of numbers indexed by time (a datetime or a datetime range). In some fields these time series are called profiles, curves, or traces. A time series of stock prices might be called a price curve. A time series of energy consumption might be called a load profile. A log of temperature values over time might be called a temperature trace.

Knowe more about  TSDB : https://en.wikipedia.org/wiki/Time_series_database

##### Installing to Influxdb database:
InfluxDB is a time series, metrics, and analytics database. It’s written in Go and has no external dependencies. That means once you install it there’s nothing else to manage (such as Redis, ZooKeeper, Cassandra, HBase, or anything else). InfluxDB is targeted at use cases for DevOps, metrics, sensor data, and real-time analytics. 

Guide to Install Influxdb on your machine :

- https://influxdb.com/docs/v0.9/introduction/installation.html

##### Getting started with Influxdb-java:

Learn the basic commands to interact with Influxdb CLI from below link.
Influxdb commands: 
- https://influxdb.com/docs/v0.9/introduction/getting_started.html

##### Installing Grafana: 
Grafana is a leading open source application for visualizing large-scale measurement data. It provides a powerful and elegant way to create, share, and explore data and dashboards from your disparate metric databases, either with your team or the world. Grafana is most commonly used for Internet infrastructure and application analytics

Pick installation method depending on your operating system : http://docs.grafana.org/installation/

##### Building dashboard using Grafana:
Building dashboard using Grafana requires running Influxdb database. After initialising the TSDB, follow the steps mentioned in the below link to visualize logs.

Getting started : http://docs.grafana.org/guides/gettingstarted/

Use custom developed Grafana templates : http://play.grafana.org/

