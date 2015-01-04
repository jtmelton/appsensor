Storage Providers
=========

A storage provider is the component that is used to save/retrieve the core data of the appsensor system. 

A storage provider SHOULD offer persistence for [events](../master/appsensor-core/src/main/java/org/owasp/appsensor/core/Event.java), [attacks](../master/appsensor-core/src/main/java/org/owasp/appsensor/core/Attack.java) and [responses](../master/appsensor-core/src/main/java/org/owasp/appsensor/core/Response.java). The duration of persistence and rollover policy is at the discretion of the storage provider, and configuration should be documented.

Reference implementations are offered for in-memory, file, SQL (via JPA2), and MongoDB. Please use these as a reference.

If you would like to provide a new implementation or improve an existing one, please create an issue.
