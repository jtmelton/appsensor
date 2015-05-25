package org.owasp.appsensor.demo.advice;

import java.util.Arrays;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.DetectionSystem;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.KeyValuePair;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.event.EventManager;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;

@ControllerAdvice
class GlobalExceptionHandlerAdvice {
	
	@Inject 
	private AppSensorClient appSensorClient;
	
	@Inject 
	private EventManager ids;
	
    public static final String DEFAULT_ERROR_VIEW = "error";

    @ExceptionHandler(value = Exception.class)
    public ModelAndView defaultErrorHandler(HttpServletRequest req, Exception e) throws Exception {

    	// use logged in username
    	User user = new User(getUsername(req));
    	//use class name for grouping (detection point id)
    	DetectionPoint detectionPoint = new DetectionPoint("Exception Handling", "UnhandledException");
    	Event event = new Event(user, detectionPoint, getDetectionSystem());
    	KeyValuePair metadata = new KeyValuePair("exception.content", ExceptionUtils.getStackTrace(e));
    	event.setMetadata(Arrays.asList(metadata));
    	ids.addEvent(event);
    	
        ModelAndView mav = new ModelAndView();
        mav.addObject("exception", e);
        mav.addObject("url", req.getRequestURL());
        mav.setViewName(DEFAULT_ERROR_VIEW);
        return mav;
    }
    
    private String getUsername(HttpServletRequest req) {
    	//default to IP
    	String username = req.getRemoteAddr();
    	
    	if (req.getSession(false) != null && req.getSession(false).getAttribute("LOGGED_IN_USER") != null) {
    		username = (String)req.getSession(false).getAttribute("LOGGED_IN_USER");
    	}
    	
    	return username;
    }
    
    private DetectionSystem getDetectionSystem() {
    	return new DetectionSystem(
    			appSensorClient.getConfiguration().getServerConnection().getClientApplicationIdentificationHeaderValue());
    }
    
}