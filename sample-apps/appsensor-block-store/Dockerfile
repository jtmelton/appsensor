FROM anapsix/alpine-java
VOLUME /tmp
ADD target/appsensor-block-store-2.2.0.jar app.jar
ADD block-store.yml block-store.yml
RUN bash -c 'touch /app.jar'
ENV APPSENSOR_WEB_SOCKET_HOST_URL=ws://localhost:8085/dashboard
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar", "server", "block-store.yml"]
