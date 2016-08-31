# Web Services Client Libraries
----
In order to generate client libraries for [AppSensor web services REST API](https://github.com/jtmelton/appsensor/tree/master/execution-modes/appsensor-ws-rest-server)  in different languages( Java, Python, C#, Ruby,...) these two files are required :

 - **swagger.json** : API specification file ( one file for all languages).
 - **pom.xml**  : Build file, which is different for each language.
 
 **swagger.json** is an API specification file generated out of the web services REST Api using instructions [here]( specfile.md).  After generating the swagger.json file, it should be copied to the desired client library folder, for example "appsensor\client-libs\java".
 
 **pom.xml**  build file is  different for each language. The client library will be generated using the [Swagger Code Genration MVN Plugin](https://github.com/swagger-api/swagger-codegen/tree/master/modules/swagger-codegen-maven-plugin) which is configured in the pom.xml. 
 ## **Client library generation**

The client libraries are placed in "*AppSensor\client-libs". There is a separate folder for each language containing the above files, and a demo folder.

Using the pre-configured swagger.json file, the client libraries are generated to communicate with the AppSensor web services via **localhost:8085** address(whihc is based on the configuration settings of **appsensor\sample-apps\appsensor-ws-rest-server-boot**). This base host and address can be changed at run time using the generated client api (can be found in demo source codes). 

----
 ### Java Library 
 Having two above files(swagger.json, pom.xml) in the "AppSensor\client-libs\Java" directory then run the following command:
```
mvn install
```
After executing the above command the generated "*target*" folder will contain the **.jar** file and the corresponding source files.
 - **Jar Files**: The jar file(s) will be available in the root of the "target" folder. There are two files 
  >* clientLibs.java-1.0.jar
  >* clientLibs.java-1.0-jar-with-dependencies.jar   ( all the required dependencies are included).
 This "jar" file should be available in the build path of any Java application using this Java client api to connect to the AppSensor REST web services.
 
 - **Source Files**: All the generated source files are placed in the "target\generated-source" directory. If it is required to change the source files, then the pom.xml file in the "generated-sources" folder can be used to build and generating the above jar files.

- The  pom.xml  file for Java languge shoudl be configured as follow:

 ```xml
<plugin>
<groupId>io.swagger</groupId>
        <artifactId>swagger-codegen-maven-plugin</artifactId>
        <version>2.1.5</version>
         <executions>
          <execution>
             <goals>
                <goal>generate</goal>
             </goals>
             <configuration>
                   <inputSpec>swagger.json</inputSpec>                            
                   <language>java</language>
							....                     
               		<configOptions>
                    	<dateLibrary>java8</dateLibrary>								
               		</configOptions>
               <library>jersey2</library>
              </configuration>
          </execution>
         </executions>
</plugin>
 ```
 #### Java Demo application
 The demo folder contains a source file using the generated Java library to communicate with REST API. The demo application contains these functionalities:
* Gettting Server Configuration
* Adding a new Event
* Getting list of Events
 
 **Requirements :**
 1. Appsensor web services engine should be running. Some details can be found [here](https://github.com/jtmelton/appsensor/tree/master/sample-apps/appsensor-ws-rest-server-boot).
 2.  Apache TomCat or any similar jsp application server should be running( stand alone or in an IDE)
 
----
 ### Python Library  
 Having two above files(swagger.json, pom.xml) in the Python directory then run the following command:
```
mvn install
```
After executing the above command, a directory named “target\generated-sources” would be created. It contains “setup.py” file. Then in the OS command line the following commands should be entered( assuming in *"appsensor\client-libs\python"*):
```
cd target\generated-sources
python setup.py install 
```
The above command generates other files:.
- **Egg file**: It is placed in “target\generated-sources\dist” folder. This "egg" file should be imported to any Python application using Python client api to connect to the AppSensor REST web services.

- **Source Files**: All the generated source files are placed in the "target\generated-source\swagger_client" directory. If it is required to change the source files, then the pom.xml file in the "generated-sources" folder can be used to build and generating the above files.

- The  pom.xml  file for Python languge shoudl be configured as follow:

 ```xml
<plugin>
<plugin>
  <groupId>io.swagger</groupId>
                <artifactId>swagger-codegen-maven-plugin</artifactId>
                <version>2.1.5</version>
                <executions>
                    <execution>
                        <goals>
                            <goal>generate</goal>
                        </goals>
                        <configuration>                           
                            <inputSpec>swagger.json</inputSpec>                            
                            <language>python</language>
							<output>${project.build.directory}/generated-sources </output>
							<modelPackage>${project.groupId}.${project.artifactId}.model</modelPackage>
							<apiPackage>${project.groupId}.${project.artifactId}.api</apiPackage>
							<invokerPackage>${project.groupId}.${project.artifactId}.handler</invokerPackage>  
                        </configuration>
                    </execution>
                </executions>
            </plugin>
 ```
 ### Python  Demo Application
 The demo folder contains a source code using the generated Java library to communicate with REST API. The demo application contains these functionalities:
* Getting the Server Configuration
* Addng a New Event
* Getting list of Events
 
 **Requirements :**
 1. Appsensor web services engine should be running. Details can be found [here](https://github.com/jtmelton/appsensor/tree/master/sample-apps/appsensor-ws-rest-server-boot).
 2. Python should be installed.