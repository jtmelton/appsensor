package org.owasp.appsensor.demo;

import java.util.Calendar;

import org.hibernate.validator.constraints.NotEmpty;

public class Note {

	private Long id;

	@NotEmpty(message = "Note is required.")
	private String text;

	@NotEmpty(message = "Summary is required.")
	private String summary;

	private Calendar created = Calendar.getInstance();

	public Long getId() {
		return this.id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Calendar getCreated() {
		return this.created;
	}

	public void setCreated(Calendar created) {
		this.created = created;
	}

	public String getText() {
		return this.text;
	}

	public void setText(String text) {
		this.text = text;
	}

	public String getSummary() {
		return this.summary;
	}

	public void setSummary(String summary) {
		this.summary = summary;
	}
	
}