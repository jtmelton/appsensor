# Specification File Generation
----
The web services specification file (swagger.json) is used in generating the client libraries in different languages.The AppSesnor  REST web services are located in   **"appsensor\execution-modes\appsensor-ws-rest-server"**.
 The follwwing files are required :

 - **enunciate.xml** : Configuration file for the Enunciate plugin used in pom.xml
 - **pom.xml**  : Build file.
 
To generate the specification file the following instructions should be used:
* Change the current directory to the REST web services( as mentioned above)
* Executing the following command:
```
mvn install
```


After executing the above command a new directory named **swagger**( can be renamed using the enuncite.xml) will be generated in the REST web services server directory. The specification file **(swagger.json)** is located at *wsdocs\apidocs\swagger\swagger.json*

There are some configuration parameters which affect some fields of the specification file and can(should) be set in the "Enunciate.xml" file.

 - **Enunciate.xml:**
 ```xml
  <modules>
	<gwt-json-overlay disabled="true"/>
	<java-json-client disabled="true"/> 
	<php-json-client disabled="true"/>
	<ruby-json-client disabled="true"/>	
    <swagger docsSubdir="swagger"  host="localhost:8085" basePath="" >
		<scheme>http</scheme>
	</swagger>	
	<docs docsDir="wsdocs" />		
  </modules>

 ```
One of the most important fields is the **host** attribute in the  <**swagger**> element indicating the host address of the web services. This field can also be changed by editing the swagger.json file directly.
 
 Other important fields are the "base path" and the "protocol schemes" the web services are communicating in. All the web services have this address pattern:
 
 **scheme://host/basePath/REST_Web_Service_Name**
 
 For Example( if basePath is empty) :
 
 http://localhost:8085/REST_Web_Service_Name
 
 - **pom.xml**
 The build file contain a plugin (Enunciate) and the realted denpendencies to generate the specification file.
 ```xml
 <build>
		<plugins>
			<plugin>
			  <groupId>com.webcohesion.enunciate</groupId>
			  <artifactId>enunciate-maven-plugin</artifactId> 			
			  <version>2.2.0</version>
			  <executions>
			    <execution>
			      <goals>
			        <goal>docs</goal>
			      </goals>				  
			    </execution>
			  </executions>
			</plugin>
		</plugins>
	</build>
 ```
 


