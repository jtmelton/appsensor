AppSensor
=========

[![Build Status](https://travis-ci.org/jtmelton/appsensor.svg?branch=master)](https://travis-ci.org/jtmelton/appsensor)

AppSensor is a framework that provides real-time event detection and response. The initial goal is to provide application layer intrusion detection (self-defending applications), though many types of systems are possible using the framework. 

AppSensor has a [website](http://appsensor.org) with further documentation and is an [OWASP](https://www.owasp.org/index.php/AppSensor) project.

Previous releases are tracked here in the [releases](https://github.com/jtmelton/appsensor/releases). The upcoming releases and milestones are tracked in the [roadmap](https://www.owasp.org/index.php/OWASP_AppSensor_Project#tab=Road_Map_and_Getting_Involved).

The AppSensor source code is released under an MIT license. See the accompanying LICENSE.txt file for license content.

Demo Quickstart
------------

If you are just wanting to get a demo going, see the [sample-apps/DemoSetup.md](sample-apps/DemoSetup.md) guide.

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

User / Developer Quick Start
-----------

We recommend you visit http://appsensor.org/ and read the "Getting Started" page. 

If you prefer presentations, here is a [recent slide deck](http://www.slideshare.net/jtmelton/appsensor-near-real-time-event-detection-and-response)

If you prefer video, here is a [recent talk](https://www.youtube.com/watch?v=1imlD1O4HrY)

Downloads
---------

Both production and snapshot releases are available in the central maven repository

https://repo1.maven.org/maven2/org/owasp/appsensor/

An example of getting one of the dependencies is shown below: 

```xml
<dependency>
	<groupId>org.owasp.appsensor</groupId>
	<artifactId>appsensor-core</artifactId>
	<version>2.3.1</version>
</dependency>
```

Contributing
------------

Want to contribute? Great - we love the help! Start on the mailing list at owasp-appsensor-project@lists.owasp.org for help with any questions.

If you want more information about how to contribute, see the [CONTRIBUTING.md](CONTRIBUTING.md)
