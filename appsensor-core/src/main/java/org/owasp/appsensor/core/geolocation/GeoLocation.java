package org.owasp.appsensor.core.geolocation;


import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.appsensor.core.IAppsensorEntity;

/**
 * General object representing geo-location. 
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Entity
public class GeoLocation implements IAppsensorEntity {

	private static final long serialVersionUID = 7191033637677492054L;

	@Id
	@Column(columnDefinition = "integer")
	@GeneratedValue
	private String id;
	
	private double latitude = 0.0;
	private double longitude = 0.0;
	
	protected GeoLocation() {}
	
	public GeoLocation(double latitude, double longitude) {
		setLatitude(latitude);
		setLongitude(longitude);
	}
	
	public double getLatitude() {
		return latitude;
	}

	@Override
	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public GeoLocation setLatitude(double latitude) {
		this.latitude = latitude;
		
		return this;
	}

	public double getLongitude() {
		return longitude;
	}

	public GeoLocation setLongitude(double longitude) {
		this.longitude = longitude;
		
		return this;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(latitude).
				append(longitude).
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
		
		GeoLocation other = (GeoLocation) obj;
		
		return new EqualsBuilder().
				append(latitude, other.getLatitude()).
				append(longitude, other.getLongitude()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
				append("latitude", latitude).
				append("longitude", longitude).
			    toString();
	}
	
}
