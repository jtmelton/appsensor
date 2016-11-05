FROM anapsix/alpine-java
VOLUME /tmp
ADD target/appsensor-ui-2.3.0.jar app.jar
RUN bash -c 'touch /app.jar'
ENV APPSENSOR_WEB_SOCKET_HOST_URL=ws://localhost:8085/dashboard
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]
