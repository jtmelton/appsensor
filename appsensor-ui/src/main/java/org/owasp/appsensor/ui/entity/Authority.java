package org.owasp.appsensor.ui.entity;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

@Entity
@Table(name = "authorities")
public class Authority {
	
	@Id
	@Column(name = "id")
	@GeneratedValue
	private Integer id;

	@Column(name = "authority")
	private String name;

	@ManyToMany(fetch = FetchType.LAZY, mappedBy="userAuthorities")
	private Set<User> users = new HashSet<>();
	
	@ManyToMany(fetch = FetchType.LAZY, mappedBy = "authorities")
	private Set<Group> groups = new HashSet<>();

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

	public Set<Group> getGroups() {
		return groups;
	}

	public void setGroups(Set<Group> groups) {
		this.groups = groups;
	}

	@Override
	public String toString() {
		return "Authority [id=" + id + ", name=" + name + "]";	//", users=" + users + ", groups=" + groups + "	
	}
	
}
