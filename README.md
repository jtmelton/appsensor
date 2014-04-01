appsensor
=========

This is the repository for the new version (v2) of AppSensor. 

[AppSensor](https://www.owasp.org/index.php/AppSensor) project is an OWASP project that provides application layer intrusion detection.

This code is currently INCOMPLETE and under active development. 

Contributing
------------

Want to contribute? Great! Start on the mailing list at owasp-appsensor-project@lists.owasp.org

Here are a few ideas of things that could be picked up: 

CODING
- analysis engine - different versions could be built, ie stochastic vs. statistical vs. behavioral, etc. (written in java)
- web services - currently working on these, but need handlers for rest/soap in the backend (java)
- implementations of core storage components - current implementations are in-memory, but we'll want file-backed, database-backed (sql/nosql), etc. implementations (java)
- unit tests / integration tests for the analysis engine (java)
- sample detection point implementations (any language)
- sample client applications / demos using appsensor (any language)
- reporting services apis (java)
- reporting client UI - need a reference front-end to visualize and manage the data (any language, but should be web-based) - see also UX below

UX
- It would be awesome to provide a default UI for event visualization and management. This could be a big, fun project.

DOCUMENTATION
- configuration scripts / tutorials for different web / application servers. We need to show how to setup the authentication for client applications since that will be done by the web/app servers and not the analysis engine itself. Essentially, this is setup and documentation of reverse proxy configuration. We can lean heavily on web server documentation here. (documentation / scripting)
- end-user documentation guidance (documentation)
