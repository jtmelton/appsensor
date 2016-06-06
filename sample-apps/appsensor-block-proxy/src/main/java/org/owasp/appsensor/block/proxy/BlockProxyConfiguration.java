package org.owasp.appsensor.block.proxy;

import io.dropwizard.Configuration;
import io.dropwizard.client.JerseyClientConfiguration;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;

public class BlockProxyConfiguration extends Configuration {

	@NotNull
    private String blockStoreUrl;
	
	@NotNull
	private String applicationTargetUri;
	
	@Valid
    @NotNull
    private JerseyClientConfiguration httpClient = new JerseyClientConfiguration();

	@JsonProperty("httpClient")
    public JerseyClientConfiguration getJerseyClientConfiguration() {
        return httpClient;
    }

	@JsonProperty
	public String getBlockStoreUrl() {
		return blockStoreUrl;
	}

	@JsonProperty
	public void setBlockStoreUrl(String blockStoreUrl) {
		this.blockStoreUrl = blockStoreUrl;
	}

	@JsonProperty
	public String getApplicationTargetUri() {
		return applicationTargetUri;
	}

	@JsonProperty
	public void setApplicationTargetUri(String applicationTargetUri) {
		this.applicationTargetUri = applicationTargetUri;
	}
	
}