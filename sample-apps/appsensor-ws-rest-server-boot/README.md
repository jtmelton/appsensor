AppSensor WS REST Server 
==========

Before running you must first build AppSensor's modules, follow the directions in README in the project root.

Once you've built AppSensor's modules there are three ways to run the WS REST Server

Spring Boot
------------
This will run the application locally 'exploded' allowing static resource to be 'hot reloaded'
`mvn spring-boot:run`


Fat Jar
------------
This will build a jar that can be transported and run on any Java 8 host
```
mvn package
java -jar target/appsensor-ws-rest-server-boot-0.0.1-SNAPSHOT.jar
```

Docker
-----------
```
mvn package 
sudo docker build -t appsensor-ws-rest-server-boot . 
sudo docker run -d -p 8085:8085 appsensor-ws-rest-server-boot
```