package org.owasp.appsensor.demo.controller;

import javax.validation.Valid;

import org.owasp.appsensor.demo.Note;
import org.owasp.appsensor.demo.NoteRepository;
import org.owasp.appsensor.demo.NoteValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/")
public class NoteController {
	
	private final NoteRepository noteRepository;

	private final NoteValidator noteValidator;
	
	@Autowired
	public NoteController(NoteRepository noteRepository, NoteValidator noteValidator) {
		this.noteRepository = noteRepository;
		this.noteValidator = noteValidator;
	}
	
	@RequestMapping("login")
	public ModelAndView viewLogin() {
		return new ModelAndView("login");
	}

	@RequestMapping
	public ModelAndView list() {
		Iterable<Note> notes = this.noteRepository.findAll();
		return new ModelAndView("notes/list", "notes", notes);
	}

	@RequestMapping("{id}")
	public ModelAndView view(@PathVariable("id") Note note) {
		return new ModelAndView("notes/view", "note", note);
	}

	@RequestMapping(params = "form", method = RequestMethod.GET)
	public String createForm(@ModelAttribute Note note) {
		return "notes/form";
	}

	@RequestMapping(method = RequestMethod.POST)
	public ModelAndView create(@Valid Note note, BindingResult result,
			RedirectAttributes redirect) {
		if (result.hasErrors()) {
			return new ModelAndView("notes/form", "formErrors", result.getAllErrors());
		}
		note = this.noteRepository.save(note);
		redirect.addFlashAttribute("globalMessage", "Successfully created a new note");
		return new ModelAndView("redirect:/{note.id}", "note.id", note.getId());
	}

	@RequestMapping("foo")
	public String foo() {
		throw new RuntimeException("Expected exception in controller");
	}
	
	@InitBinder
	protected void initBinder(WebDataBinder binder) {
	    binder.setValidator(noteValidator);
	}

}