package org.owasp.appsensor.ui.entity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

@Entity(name = "org.owasp.appsensor.ui.entity.User")
@Table(name = "users")
public class User {
	
	@Id
	@Column(name="username", unique=true)
	private String username;
	
	@ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
	@JoinTable(name = "user_authorities", 
			joinColumns = {@JoinColumn(name = "username", nullable = false, updatable = false) }, 
			inverseJoinColumns = { @JoinColumn(name = "authority_id", nullable = false, updatable = false) })
	private Set<Authority> userAuthorities = new HashSet<>();
	
	@ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
	@JoinTable(name = "group_users",
			joinColumns = {@JoinColumn(name = "username", nullable = false, updatable = false) }, 
			inverseJoinColumns = { @JoinColumn(name = "group_id", nullable = false, updatable = false) })
	private Set<Group> groups = new HashSet<>();

	
	@ElementCollection(fetch = FetchType.EAGER)
	@CollectionTable(
			name="user_client_applications",
			joinColumns=@JoinColumn(name="username")
	)
	@Column(name="client_application_name")
	private Collection<String> clientApplications = new ArrayList<>();

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public Set<Authority> getUserAuthorities() {
		return userAuthorities;
	}

	public void setUserAuthorities(Set<Authority> userAuthorities) {
		this.userAuthorities = userAuthorities;
	}

	public Set<Group> getGroups() {
		return groups;
	}

	public void setGroups(Set<Group> groups) {
		this.groups = groups;
	}

	public Collection<String> getClientApplications() {
		return clientApplications;
	}

	public void setClientApplications(Collection<String> clientApplications) {
		this.clientApplications = clientApplications;
	}
	
	@Override
	public String toString() {
		return "User [username=" + username + ", userAuthorities=" + userAuthorities + ", groups=" + groups
				+ ", clientApplications=" + clientApplications + "]";
	}

} 
