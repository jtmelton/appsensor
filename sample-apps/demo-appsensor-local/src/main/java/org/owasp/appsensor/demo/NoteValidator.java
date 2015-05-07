package org.owasp.appsensor.demo;

import javax.annotation.PostConstruct;
import javax.inject.Named;

import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.DetectionPoint.Category;
import org.owasp.appsensor.core.DetectionSystem;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.event.EventManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import org.springframework.validation.beanvalidation.SpringValidatorAdapter;

@Named
public class NoteValidator implements Validator {

	private SpringValidatorAdapter validator;

	@Autowired
	private javax.validation.Validator jsr303Validator;
	
	@Autowired 
	private AppSensorClient appSensorClient;
	
	@Autowired 
	private EventManager ids;
	
	@PostConstruct
	public void init() {
		validator = new SpringValidatorAdapter(jsr303Validator);
	}
	
    @Override
    public boolean supports(Class<?> clazz) {
        return Note.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {

	    //jsr303
	    validator.validate(target, errors);

	    //custom rules
        Note note = (Note) target;

        if (note.getSummary() != null && note.getSummary().contains("<script>")) {
        	signalXss();
        	errors.rejectValue("summary", "xss.attempt", "You tried XSS - stop!");
        }
        
        if (note.getText() != null && note.getText().contains("<script>")) {
        	signalXss();
        	errors.rejectValue("text", "xss.attempt", "You tried XSS - stop!");
        }
        
    }
    
    private void signalXss() {
		User user = new User(getUserName());
		// AE3: High Rate of Login Attempts
		DetectionPoint detectionPoint = new DetectionPoint(Category.INPUT_VALIDATION, "IE1");
		ids.addEvent(new Event(user, detectionPoint, getDetectionSystem()));
    }
    
    private String getUserName() {
    	Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    	String userName = authentication.getName();
    	
    	// overwrite if we can be more specific
    	if (authentication instanceof UserDetails) {
    		UserDetails userDetails = (UserDetails)authentication;
    		
    		userName = userDetails.getUsername();
    	}
		
		return userName;
    }
    
    private DetectionSystem getDetectionSystem() {
    	return new DetectionSystem(
    			appSensorClient.getConfiguration().getServerConnection().getClientApplicationIdentificationHeaderValue());
    }
    
}
