AppSensor Demo Setup
=========

These instructions will help you get setup to run a demo similar to what was done for AppSecUSA 2015. (video here: https://www.youtube.com/watch?v=1imlD1O4HrY)

1. **Install Java 8**

  - follow OS-specific install process
  
2. **Get AppSensor Code**

  - clone the repo (or your fork)
  
    ```
    git clone https://github.com/jtmelton/appsensor.git
    ```
  - get into appsensor directory
  
    ```
    cd appsensor
    ```
  - install multi-module parent 
  
    ```
    mvn -N install 
    ```
  -  run the tests and install locally
  
    ```
    mvn install
    ```

3. **Install MySQL**

  - follow OS-specific install process (this demo assumes localhost)
  
4. **Load Data into MySQL**

  - Run commands in this file: https://github.com/jtmelton/appsensor/blob/master/appsensor-ui/src/main/resources/db/scripts/V1_Initial_Schema_Creation.sql (including commented lines - uncomment and run)

5. **Start REST / WebSocket Server**

  - go to this directory: https://github.com/jtmelton/appsensor/tree/master/sample-apps/appsensor-ws-rest-server-with-websocket-boot
  - run this command:
  
  ```
  mvn spring-boot:run -DAPPSENSOR_WEB_SOCKET_HOST_URL=ws://localhost:8085/dashboard
  ```

6. **Start REST Client Data Generator**

  - go to this directory: https://github.com/jtmelton/appsensor/tree/master/sample-apps/appsensor-ws-rest-client-boot-data-generator
  - run this command:
  
  ```
  mvn spring-boot:run
  ```

7. **Start AppSensorUI**

  - go to this directory: https://github.com/jtmelton/appsensor/tree/master/appsensor-ui
  - run this command:
  
  ```
  mvn spring-boot:run -DAPPSENSOR_REST_REPORTING_ENGINE_URL=http://localhost:8085 -DAPPSENSOR_CLIENT_APPLICATION_ID_HEADER_NAME=X-Appsensor-Client-Application-Name2 -DAPPSENSOR_CLIENT_APPLICATION_ID_HEADER_VALUE=myclientapp -DAPPSENSOR_WEB_SOCKET_HOST_URL=ws://localhost:8085/dashboard -Dspring.datasource.url=jdbc:mysql://localhost/appsensor -Dspring.datasource.username=appsensor_user -Dspring.datasource.password=appsensor_pass
  ```
  
8. **Login**

  - open your browser to : http://localhost:8084
  - When prompted login with user ```analyst``` and password ```analyst```.
  
  

This set of instructions should get the demo going for you. If you have problems, please file an issue: https://github.com/jtmelton/appsensor/issues/new.
