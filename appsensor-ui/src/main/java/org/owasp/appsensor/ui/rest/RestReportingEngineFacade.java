package org.owasp.appsensor.ui.rest;

import javax.annotation.PostConstruct;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;

import org.owasp.appsensor.core.KeyValuePair;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class RestReportingEngineFacade {
	
	private static String NEWLINE = System.getProperty("line.separator");
	
	@Value("${APPSENSOR_REST_REPORTING_ENGINE_URL}")
	private String restReportingEngineUrl;
	
	@Value("${APPSENSOR_CLIENT_APPLICATION_ID_HEADER_NAME}")
	private String clientApplicationIdName;

	@Value("${APPSENSOR_CLIENT_APPLICATION_ID_HEADER_VALUE}")
	private String clientApplicationIdValue;
	
	private WebTarget target;
	
	public RestReportingEngineFacade() { }
	
	public String getServerConfiguration() {
		return target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("server-config")
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(String.class);
	}
	
	public KeyValuePair getBase64EncodedServerConfiguration() {
		return target
				.path("api")
				.path("v1.0")
				.path("reports")
				.path("server-config-base64")
				.request()
				.header(clientApplicationIdName, clientApplicationIdValue)
				.get(KeyValuePair.class);
	}
	
	@PostConstruct
	private void initializeData() {
		if (restReportingEngineUrl == null || clientApplicationIdName == null || clientApplicationIdValue == null) {
			StringBuilder sb = new StringBuilder("AppSensorUI must have the appropriate configuration values enabled properly.");
			
			if (restReportingEngineUrl == null) {
				sb.append(NEWLINE).append("The setting for 'APPSENSOR_REST_REPORTING_ENGINE_URL' must be set.");
			}
			
			if (clientApplicationIdName == null) {
				sb.append(NEWLINE).append("The setting for 'APPSENSOR_CLIENT_APPLICATION_ID_HEADER_NAME' must be set.");
			}
			
			if (clientApplicationIdValue == null) {
				sb.append(NEWLINE).append("The setting for 'APPSENSOR_CLIENT_APPLICATION_ID_HEADER_VALUE' must be set.");
			}
			
			throw new IllegalStateException(sb.toString());
		}
		
		target = ClientBuilder.newClient().target(restReportingEngineUrl);
	}
}
