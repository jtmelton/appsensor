FROM anapsix/alpine-java

VOLUME /tmp
ADD target/appsensor-ui-2.3.2.jar app.jar

ENV DOCKERIZE_VERSION="0.2.0"
ENV DOCKERIZE_URL="https://github.com/jwilder/dockerize/releases/download/v$DOCKERIZE_VERSION"
ENV DOCKERIZE_PKG="dockerize-linux-amd64-v$DOCKERIZE_VERSION.tar.gz"

RUN     apk update \                                                                                                                                                                                                                        
   &&   apk add ca-certificates wget \                                                                                                                                                                                                      
   &&   update-ca-certificates   
    
RUN wget -q $DOCKERIZE_URL/$DOCKERIZE_PKG -O $DOCKERIZE_PKG
RUN tar -C /usr/local/bin -xzvf $DOCKERIZE_PKG 
   
#ADD wait-for-it.sh wait-for-it.sh
#RUN chmod +x wait-for-it.sh
RUN bash -c 'touch /app.jar'
ENV APPSENSOR_WEB_SOCKET_HOST_URL=ws://localhost:8085/dashboard
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]
