package org.owasp.appsensor.block.proxy.domain;

import javax.validation.constraints.NotNull;

import org.joda.time.DateTime;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Preconditions;
import com.google.common.collect.ComparisonChain;

public class Block implements Comparable<Block> {

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
	
	public boolean applies(String ipAddress, String resource, DateTime time) {
		boolean applies = false;
		
		Preconditions.checkNotNull(ipAddress);
		Preconditions.checkNotNull(resource);
		Preconditions.checkNotNull(time);
		
		if(this.endTime.isBefore(time)) {
			// this one's expired - bail
			return false;
		}
		
		boolean ipAddressMatch = ipAddress.equals(this.ipAddress);
		boolean resourceMatch = resource.equals(this.resource);
		
		if(appliesToIpAddress() && appliesToResource()) {

			// this block applies to both - both must match
			applies = ipAddressMatch && resourceMatch;
		} else if(appliesToIpAddress()) {
			
			// only ip blocked - any thing matching this ip should be blocked
			applies = ipAddressMatch;
		} else if(appliesToResource()) {
			
			// only resource blocked - any thing matching this ip should be blocked
			applies = resourceMatch;
		}
		
		return applies;
	}
	
	@Override
	public String toString() {
		return "BlockRequest [ipAddress=" + ipAddress + ", resource=" + resource + ", endTime=" + endTime + "]";
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

	@Override
	public int compareTo(Block that) {
		ComparisonChain chain = ComparisonChain.start();
		
		if(ipAddress != null && that.ipAddress != null) {
			chain = chain.compare(ipAddress, this.ipAddress);
		}
		
		if(resource != null && that.resource != null) {
			chain = chain.compare(resource, this.resource);
		}
		
		if(endTime != null && that.endTime != null) {
			chain = chain.compare(endTime, this.endTime);
		}
		
		return chain.result();
	}
    
}
