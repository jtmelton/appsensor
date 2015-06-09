package org.owasp.appsensor.demo;

public interface NoteRepository {

	Iterable<Note> findAll();

	Note save(Note note);

	Note findNote(Long id);

}