package org.owasp.appsensor.core;

import java.net.InetAddress;

import javax.inject.Named;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.codehaus.jackson.annotate.JsonProperty;
import org.owasp.appsensor.core.geolocation.GeoLocation;
import org.owasp.appsensor.core.geolocation.GeoLocator;
import org.springframework.beans.factory.annotation.Autowired;

import com.google.common.net.InetAddresses;

/**
 * The IP Address for the user, optionally provided by the client application. 
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Entity
@Named
@XmlAccessorType(XmlAccessType.FIELD)
public class IPAddress implements IAppsensorEntity {

	private static final long serialVersionUID = -2325233176848461722L;

	@Id
	@Column(columnDefinition = "integer")
	@GeneratedValue
	private String id;
	
	private String address;
	
	@JsonProperty("geoLocation")
	private GeoLocation geoLocation;

	@Autowired(required = false)
	private transient GeoLocator geoLocator;

	protected IPAddress() {}
	
	public IPAddress(String address, GeoLocation geoLocation) {
		if (! InetAddresses.isInetAddress(address)) {
			throw new IllegalArgumentException("IP Address string is invalid: " + address);
		}
		this.address = address;
		this.geoLocation = geoLocation;
	}
	
	public IPAddress fromString(String ipString) throws IllegalArgumentException {
		if (! InetAddresses.isInetAddress(ipString)) {
			throw new IllegalArgumentException("IP Address string is invalid: " + ipString);
		}

		GeoLocation localGeo = null;
		
		if(geoLocator != null) {
			localGeo = geoLocator.readLocation(asInetAddress(ipString));
		}

		return new IPAddress(ipString, localGeo);
	}
	
	public InetAddress asInetAddress() {
		return InetAddresses.forString(getAddressAsString());
	}
	
	private InetAddress asInetAddress(String ipString) {
		return InetAddresses.forString(ipString);
	}

	public IPAddress setAddress(String address) {
		this.address = address;
		
		return this;
	}

	@Override
	public String getId() {
		return id;
	}

	@Override
	public void setId(String id) {
		this.id = id;
	}

	public String getAddress() {
		return address;
	}
	
	public String getAddressAsString() {
		return address;
	}
	
	@JsonProperty("geoLocation")
	public GeoLocation getGeoLocation() {
		return geoLocation;
	}
	
	@JsonProperty("geoLocation")
	public IPAddress setGeoLocation(GeoLocation geoLocation) {
		this.geoLocation = geoLocation;
		
		return this;
	}
	
	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(address).
				toHashCode();
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		
		IPAddress other = (IPAddress) obj;
		
		return new EqualsBuilder().
				append(address, other.getAddressAsString()).
				append(geoLocation, other.getGeoLocation()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
				append("address", address).
				append("geoLocation", geoLocation).
			    toString();
	}
	
}
