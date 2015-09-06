AppSensor ELK Stack Integration Documentation
=========

This document outlines the mechanisms required to integrate the output of the appsensor system with the ELK (elasticsearch - logstash - kibana) stack.

Acknowledgements
--------

This work was done by Sumanth Damarla as part of the 2015 OWASP Summer of Code Sprint.

Instructions
--------

### APPSENSOR DOCUMENTATION

This documentation focuses on configuring ELK Stack with OWASP AppSensor for visualizing the logs which highlights the attacks performed on an application.

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

### Documentation Contents

1. *Software prerequisites.*
2. *Description of data extracted from Appsensor syslog.*
3. *Intro to ELK Stack and Installing procedure.*
4. *Installing Tomcat Server in Ubuntu.*
5. *Building AppSensor Environment.*
6. *Deploying sample app in standalone container.*
7. *Deploying sample app in IDE-managed container.*
8. *Configuring rsyslog file for logging syslog data in syslog file.*
9. *Providing Syslog as input for Logstash.*
10. *Setting up appsensor-ws-rest-server-with-websocket-boot environment.*
11. *Setting up appsensor-ws-rest-client-boot-data-generator environment.*
12. *Display Syslog messages.*
13. *Logstash Filters used for parsing Appsensor syslogs.*
14. *Building dashboard using Kibana.*

