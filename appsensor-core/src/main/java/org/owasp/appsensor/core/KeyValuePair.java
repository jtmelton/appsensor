package org.owasp.appsensor.core;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
public class KeyValuePair implements Serializable {
 
	private static final long serialVersionUID = 7159160142952459590L;

	@Id
	@Column
	@GeneratedValue
	private Integer id;
	
	private String key;
    private String value;

    public KeyValuePair() { }
    
    public KeyValuePair(String key, String value) {
    	this.key = key;
    	this.value = value;
    }

    public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	@Override
    public int hashCode() {
    	int hashKey = key != null ? key.hashCode() : 0;
    	int hashValue = value != null ? value.hashCode() : 0;

    	return (hashKey + hashValue) * hashValue + hashKey;
    }

    @Override
    public boolean equals(Object other) {
    	if (this == other) {
    		return true;
    	}
    	if (other == null) {
    		return false;
    	}
    	if (getClass() != other.getClass()) {
    		return false;
    	}
    	if (other instanceof KeyValuePair) {
    		KeyValuePair otherPair = (KeyValuePair) other;
    		return 
    		((  this.key == otherPair.key ||
    			( this.key != null && otherPair.key != null &&
    			  this.key.equals(otherPair.key))) &&
    		 (	this.value == otherPair.value ||
    			( this.value != null && otherPair.value != null &&
    			  this.value.equals(otherPair.value))) );
    	}

    	return false;
    }

    @Override
    public String toString() { 
           return "(" + key + ", " + value + ")"; 
    }

}