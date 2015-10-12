package org.owasp.appsensor.block.store.domain;

import javax.validation.constraints.NotNull;

import org.joda.time.DateTime;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Block {

    @JsonProperty
    private String ipAddress;

    @JsonProperty
    private String resource;

    @NotNull
    @JsonProperty
    private DateTime endTime;
    
    public Block() { }
    
    public Block(String ipAddress, String resource, DateTime endTime) {
    	this.setIpAddress(ipAddress);
    	this.setResource(resource);
    	this.setEndTime(endTime);
    }

	public String getIpAddress() {
		return ipAddress;
	}

	public Block setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
		return this;
	}

	public String getResource() {
		return resource;
	}

	public Block setResource(String resource) {
		this.resource = resource;
		return this;
	}

	public DateTime getEndTime() {
		return endTime;
	}

	public Block setEndTime(DateTime endTime) {
		this.endTime = endTime;
		return this;
	}
	
	public boolean appliesToIpAddress() {
		return ipAddress != null;
	}
	
	public boolean appliesToResource() {
		return resource != null;
	}
	
	public boolean isActive(DateTime time) {
		return endTime.isAfter(time);
	}
	
	@Override
	public String toString() {
		return "Block [ipAddress=" + ipAddress + ", resource=" + resource + ", endTime=" + endTime + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((ipAddress == null) ? 0 : ipAddress.hashCode());
		result = prime * result + ((endTime == null) ? 0 : endTime.hashCode());
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
		Block other = (Block) obj;
		if (ipAddress == null) {
			if (other.ipAddress != null)
				return false;
		} else if (!ipAddress.equals(other.ipAddress))
			return false;
		if (endTime == null) {
			if (other.endTime != null)
				return false;
		} else if (!endTime.equals(other.endTime))
			return false;
		if (resource == null) {
			if (other.resource != null)
				return false;
		} else if (!resource.equals(other.resource))
			return false;
		return true;
	}
    
}
