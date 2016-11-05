appsensor-ui
==========

Before running you must first build AppSensor's modules, follow the directions in README in the project root.

Once you've built AppSensor's modules there are three ways to run the appsensor-ui

Spring Boot
------------
This will run the application locally 'exploded' allowing static resource to be 'hot reloaded'
```
mvn spring-boot:run -DAPPSENSOR_REST_REPORTING_ENGINE_URL=http://localhost:8085 -DAPPSENSOR_CLIENT_APPLICATION_ID_HEADER_NAME=X-Appsensor-Client-Application-Name2 -DAPPSENSOR_CLIENT_APPLICATION_ID_HEADER_VALUE=myclientapp -DAPPSENSOR_WEB_SOCKET_HOST_URL=ws://localhost:8085/dashboard -Dspring.datasource.url=jdbc:mysql://localhost/appsensor -Dspring.datasource.username=appsensor_user -Dspring.datasource.password=appsensor_pass
```

Fat Jar
------------
This will build a jar that can be transported and run on any Java 8 host
```
mvn package
java -jar target/appsensor-ui-2.3.0.jar -DAPPSENSOR_REST_REPORTING_ENGINE_URL=http://localhost:8085 -DAPPSENSOR_CLIENT_APPLICATION_ID_HEADER_NAME=X-Appsensor-Client-Application-Name2 -DAPPSENSOR_CLIENT_APPLICATION_ID_HEADER_VALUE=myclientapp -DAPPSENSOR_WEB_SOCKET_HOST_URL=ws://localhost:8085/dashboard -Dspring.datasource.url=jdbc:mysql://localhost/appsensor -Dspring.datasource.username=appsensor_user -Dspring.datasource.password=appsensor_pass
```

Docker
-----------
This container does not implement TLS and is intended for development. Please harden the image if you intend
to run in a container in production.

Default ENV overridable with -e
```
APPSENSOR_REST_REPORTING_ENGINE_URL=http://localhost:8085
APPSENSOR_CLIENT_APPLICATION_ID_HEADER_NAME=X-Appsensor-Client-Application-Name2
APPSENSOR_CLIENT_APPLICATION_ID_HEADER_VALUE=myclientapp
APPSENSOR_WEB_SOCKET_HOST_URL=ws://localhost:8085/dashboard
spring.datasource.url=jdbc:mysql://localhost/appsensor
spring.datasource.username=appsensor_user
spring.datasource.password=appsensor_pass
```

run with docker
```
mvn package docker:build

docker run -d -p 8084:8084 appsensor/appsensor-ui
```
