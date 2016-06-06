package org.owasp.appsensor.block.store.domain;

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;

public class BlockRequest {

    @JsonProperty
    private String ipAddress;

    @JsonProperty
    private String resource;

    @NotNull
    @JsonProperty
    private Long milliseconds;

    public BlockRequest() { }
    
    public BlockRequest(String ipAddress, String resource, Long milliseconds) {
    	this.ipAddress = ipAddress;
    	this.resource = resource;
    	this.milliseconds = milliseconds;
    }
    
	public String getIpAddress() {
		return ipAddress;
	}

	public BlockRequest setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
		return this;
	}

	public String getResource() {
		return resource;
	}

	public BlockRequest setResource(String resource) {
		this.resource = resource;
		return this;
	}

	public Long getMilliseconds() {
		return milliseconds;
	}

	public BlockRequest setMilliseconds(Long milliseconds) {
		this.milliseconds = milliseconds;
		return this;
	}
	
	public boolean appliesToIpAddress() {
		return ipAddress != null;
	}
	
	public boolean appliesToResource() {
		return resource != null;
	}
	
	@Override
	public String toString() {
		return "BlockRequest [ipAddress=" + ipAddress + ", resource=" + resource + ", milliseconds=" + milliseconds + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((ipAddress == null) ? 0 : ipAddress.hashCode());
		result = prime * result + ((milliseconds == null) ? 0 : milliseconds.hashCode());
		result = prime * result + ((resource == null) ? 0 : resource.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		BlockRequest other = (BlockRequest) obj;
		if (ipAddress == null) {
			if (other.ipAddress != null)
				return false;
		} else if (!ipAddress.equals(other.ipAddress))
			return false;
		if (milliseconds == null) {
			if (other.milliseconds != null)
				return false;
		} else if (!milliseconds.equals(other.milliseconds))
			return false;
		if (resource == null) {
			if (other.resource != null)
				return false;
		} else if (!resource.equals(other.resource))
			return false;
		return true;
	}
    
}
