Spring Security Setup
=========

The steps below describe information you'll need in addition to the standard setup guide in order to understand the spring security integration and get it going.

Exposing Context Repository
------------

* There is a custom security context repository (AppSensorSecurityContextRepository) that must
	be available as a bean in order for the appsensor <--> spring security integration to work properly. 
	Below is an example of what that might look like using Java configuration:
	
	```java
	@Bean
    public SecurityContextRepository securityContextRepository(){
        return new AppSensorSecurityContextRepository();
    }
    ```

Applying Context Repository
----------------------------------

* The other requirement of the integration is to enable the custom security context repository 
	when configuring the `HttpConfig` object. An example is below: 
	
	```java
	protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                ...
                .and()
            .formLogin()
                ...
                .and()
            .securityContext()
            	.securityContextRepository(securityContextRepository)
            	.and()
            ...
    }
	```
 
