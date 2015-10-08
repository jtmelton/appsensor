AppSensor
=========

[![Build Status](https://travis-ci.org/jtmelton/appsensor.svg?branch=master)](https://travis-ci.org/jtmelton/appsensor)

AppSensor is a framework that provides real-time event detection and response. The initial goal is to provide application layer intrusion detection, though many types of systems are possible using the framework. 

AppSensor has a [website](http://appsensor.org) with further documentation and is an [OWASP](https://www.owasp.org/index.php/AppSensor) project.

This code is actively being developed. There was a 2.0 release in January 2015. The upcoming releases and milestones are tracked in the [roadmap](https://www.owasp.org/index.php/OWASP_AppSensor_Project#tab=Road_Map_and_Getting_Involved).

The AppSensor source code is released under an MIT license. See the accompanying LICENSE.txt file.

Building
--------

AppSensor is a multi-module maven project. The project requires Java version 7 or higher. Building is generally handled by the following steps 

- clone the repo (or your fork)

    ```
    git clone https://github.com/jtmelton/appsensor.git
    ```

- get into appsensor directory

    ```
    cd appsensor
    ```

- install multi-module parent - one time requirement per version

    ```
    mvn -N install 
    ```

-  run the tests - done every time you make changes

    ```
    mvn test
    ```

Documentation
-------------

For an extensive book documenting the concepts (ideas) behind AppSensor, go to the [OWASP](https://www.owasp.org/index.php/OWASP_AppSensor_Project) site and download the PDF. 

If you're looking for in-depth user or developer documentation, visit http://appsensor.org/ 

Quick Start
-----------

We recommend you visit http://appsensor.org/ and read the "Getting Started" page.

Downloads
---------

Both production and snapshot releases are available in the central maven repository

https://repo1.maven.org/maven2/org/owasp/appsensor/

An example of getting one of the dependencies is shown below: 

```xml
<dependency>
	<groupId>org.owasp.appsensor</groupId>
	<artifactId>appsensor-core</artifactId>
	<version>2.0.1</version>
</dependency>
```

Contributing
------------

Want to contribute? Great - we love the help! Start on the mailing list at owasp-appsensor-project@lists.owasp.org for help with any questions.

Ideas for enhancements (as well as any bugs) are filed on the issues page: https://github.com/jtmelton/appsensor/issues
