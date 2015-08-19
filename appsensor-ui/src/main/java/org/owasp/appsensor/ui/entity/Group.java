package org.owasp.appsensor.ui.entity;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

@Entity
@Table(name = "groups")
public class Group {
	
	@Id
	@Column(name = "id")
	@GeneratedValue
	private Integer id;
	
	@Column(name = "group_name")
	private String name;

	@ManyToMany(fetch = FetchType.LAZY, mappedBy = "groups")
	private Set<User> users = new HashSet<>();

	@ManyToMany(targetEntity=Authority.class, fetch = FetchType.EAGER, cascade = CascadeType.ALL)
	@JoinTable(name = "group_authorities", 
			joinColumns = {@JoinColumn(name = "group_id", nullable = false, updatable = false) }, 
			inverseJoinColumns = { @JoinColumn(name = "authority_id", nullable = false, updatable = false) })
	private Set<Authority> authorities = new HashSet<>();

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Set<User> getUsers() {
		return users;
	}

	public void setUsers(Set<User> users) {
		this.users = users;
	}

	public Set<Authority> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(Set<Authority> authorities) {
		this.authorities = authorities;
	}

	@Override
	public String toString() {
		return "Group [id=" + id + ", name=" + name + ", authorities=" + authorities + "]";	//users=" + users + ", 
	}
	
}
