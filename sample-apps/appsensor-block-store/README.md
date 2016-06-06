AppSensor Block Store
==============
A lightweight in memory store that recieves block requests emitted from AppSensor and responds to requests for block information from the AppSensor Block Proxy.

Before running you must first build AppSensor's modules, follow the directions in the README in the project root.

Once you've built AppSensor's Modules there are two ways to run the Block Store

Fat Jar
--------------
This will build a jar that can run on any Java 8 host.

```
mvn package
java -jar target/appsensor-block-store-2.2.0.jar server block-store.yml
```

Docker
--------------
This container does not implement TLS and is intended for development. Please harden the image if you intend to run in a container in production.

Default EVN overridable with -e

If you wish to alter server configurations edit block-store.yml before building.

In default configuration add `-p 8091:8091` to expose server administration interface
```
mvn package docker:build
docker run -d -p 8090:8090 appsensor/appsensor-block-store-2.2.0.jar 
```
