package org.owasp.appsensor.demo;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

public class InMemoryNoteRepository implements NoteRepository {

	private static AtomicLong counter = new AtomicLong();

	private final ConcurrentMap<Long, Note> notes = new ConcurrentHashMap<Long, Note>();

	@Override
	public Iterable<Note> findAll() {
		return this.notes.values();
	}

	@Override
	public Note save(Note note) {
		Long id = note.getId();
		if (id == null) {
			id = counter.incrementAndGet();
			note.setId(id);
		}
		this.notes.put(id, note);
		return note;
	}

	@Override
	public Note findNote(Long id) {
		return this.notes.get(id);
	}

}