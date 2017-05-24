package org.owasp.appsensor.core;

import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.*;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.appsensor.core.rule.Rule;
import org.owasp.appsensor.core.util.DateUtils;

/**
 * An attack can be added to the system in one of two ways:
 * <ol>
 * 		<li>Analysis is performed by the event analysis engine and determines an attack has occurred</li>
 * 		<li>Analysis is performed by an external system (ie. WAF) and added to the system.</li>
 * </ol>
 *
 * The key difference between an {@link Event} and an {@link Attack} is that an {@link Event}
 * is "suspicous" whereas an {@link Attack} has been determined to be "malicious" by some analysis.
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Entity
public class Attack implements IAppsensorEntity {

	private static final long serialVersionUID = 7231666413877649836L;

	@Id
	@Column(columnDefinition = "integer")
	@GeneratedValue

	private String id;

	/** User who triggered the attack, could be anonymous user */
	@ManyToOne(cascade = CascadeType.ALL)
	private User user;

	/** Detection Point that was triggered */
	@ManyToOne(cascade = CascadeType.ALL)
	private DetectionPoint detectionPoint;

	/** When the attack occurred */
	@Column
	private String timestamp;

	/**
	 * Identifier label for the system that detected the attack.
	 * This will be either the client application, or possibly an external
	 * detection system, such as syslog, a WAF, network IDS, etc.  */
	@ManyToOne(cascade = CascadeType.ALL)
	private DetectionSystem detectionSystem;

	/**
	 * The resource being requested when the attack was triggered, which can be used
     * later to block requests to a given function.
     */
	@ManyToOne(cascade = CascadeType.ALL)
    private Resource resource;

	/** Rule that was triggered */
	@ManyToOne(cascade = CascadeType.ALL)
	private Rule rule;

	/** Represent extra metadata, anything client wants to send */
	@ElementCollection
	@OneToMany(cascade = CascadeType.ALL)
	private Collection<KeyValuePair> metadata = new ArrayList<>();

    public Attack () { }

    public Attack (User user, DetectionPoint detectionPoint, DetectionSystem detectionSystem) {
		this(user, detectionPoint, DateUtils.getCurrentTimestampAsString(), detectionSystem);
	}

	public Attack (User user, DetectionPoint detectionPoint, String timestamp, DetectionSystem detectionSystem) {
		setUser(user);
		setDetectionPoint(detectionPoint);
		setTimestamp(timestamp);
		setDetectionSystem(detectionSystem);
	}

	public Attack (User user, DetectionPoint detectionPoint, String timestamp, DetectionSystem detectionSystem, Resource resource) {
		setUser(user);
		setDetectionPoint(detectionPoint);
		setTimestamp(timestamp);
		setDetectionSystem(detectionSystem);
		setResource(resource);
	}

	public Attack (Event event) {
		setUser(event.getUser());
		setDetectionPoint(event.getDetectionPoint());
		setTimestamp(event.getTimestamp());
		setDetectionSystem(event.getDetectionSystem());
		setResource(event.getResource());
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public User getUser() {
		return user;
	}

	public Attack setUser(User user) {
		this.user = user;
		return this;
	}

	public DetectionPoint getDetectionPoint() {
		return detectionPoint;
	}

	public Attack setDetectionPoint(DetectionPoint detectionPoint) {
		this.detectionPoint = detectionPoint;
		return this;
	}

	public String getTimestamp() {
		return timestamp;
	}

	public Attack setTimestamp(String timestamp) {
		this.timestamp = timestamp;
		return this;
	}

	public DetectionSystem getDetectionSystem() {
		return detectionSystem;
	}

	public Attack setDetectionSystem(DetectionSystem detectionSystem) {
		this.detectionSystem = detectionSystem;
		return this;
	}

	public Resource getResource() {
		return resource;
	}

	public Attack setResource(Resource resource) {
		this.resource = resource;
		return this;
	}

	public Rule getRule() {
		return this.rule;
	}

	public Attack setRule(Rule rule) {
		this.rule = rule;
		return this;
	}

	public Collection<KeyValuePair> getMetadata() {
		return metadata;
	}

	public void setMetadata(Collection<KeyValuePair> metadata) {
		this.metadata = metadata;
	}

	public String getName() {
		String name = "";

		if (this.rule == null) {
			name = this.detectionPoint.getLabel();
		} else {
			name = this.rule.getName() == null ? this.rule.getGuid() : this.rule.getName();
		}

		return name;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(user).
				append(detectionPoint).
				append(timestamp).
				append(detectionSystem).
				append(resource).
				append(metadata).
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

		Attack other = (Attack) obj;

		return new EqualsBuilder().
				append(user, other.getUser()).
				append(detectionPoint, other.getDetectionPoint()).
				append(timestamp, other.getTimestamp()).
				append(detectionSystem, other.getDetectionSystem()).
				append(resource, other.getResource()).
				append(metadata, other.getMetadata()).
				isEquals();
	}

	@Override
	public String toString() {
		return new ToStringBuilder(this).
			       append("user", user).
			       append("detectionPoint", detectionPoint).
			       append("rule", rule).
			       append("timestamp", timestamp).
			       append("detectionSystem", detectionSystem).
			       append("resource", resource).
			       append("metadata", metadata).
			       toString();
	}

}