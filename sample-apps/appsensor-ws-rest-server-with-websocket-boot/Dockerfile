FROM anapsix/alpine-java
VOLUME /tmp
ADD target/appsensor-ws-rest-server-with-websocket-boot-0.0.1-SNAPSHOT.jar app.jar
RUN bash -c 'touch /app.jar'
ENV APPSENSOR_WEB_SOCKET_HOST_URL=ws://localhost:8085/dashboard
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]
