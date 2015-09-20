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

