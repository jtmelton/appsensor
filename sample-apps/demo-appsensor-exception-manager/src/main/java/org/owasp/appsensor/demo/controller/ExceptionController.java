package org.owasp.appsensor.demo.controller;

import java.util.Arrays;
import java.util.Collection;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.DetectionSystem;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.KeyValuePair;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.event.EventManager;
import org.owasp.appsensor.demo.ExceptionCache;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

/**
 */
@Controller
@RequestMapping("/")
public class ExceptionController {

	@Inject 
	private AppSensorClient appSensorClient;
	
	@Inject 
	private EventManager ids;
	
	public ExceptionController() { }
	
	@RequestMapping(value = "login", method = RequestMethod.GET)
	public ModelAndView viewLogin() {
		return new ModelAndView("login");
	}
	
	@RequestMapping(value = "login", method = RequestMethod.POST)
	public void processLogin(@RequestParam String username, @RequestParam String password, HttpServletRequest request, HttpServletResponse response) throws Exception {
		if("user".equals(username) && "password".equals(password)) {
			// good login
			request.getSession().setAttribute("LOGGED_IN_USER", username);
			response.sendRedirect("/");
		}
		
		response.sendRedirect("/login?error=InvalidCredentials");
	}

	@RequestMapping
	public ModelAndView list() {
		return new ModelAndView("content/errorlist");
	}
	
	@RequestMapping("generateerror")
	public ModelAndView viewGenerateError() {
		return new ModelAndView("content/generateerror");
	}

	@RequestMapping(value = "api/generate", method = RequestMethod.GET)
	@ResponseBody
	public Integer generateException(@RequestParam("exceptionLabel") String exceptionLabel, HttpServletRequest req) {
		try {
			throw new RuntimeException(exceptionLabel);
		} catch(RuntimeException re) {
			// use logged in username
	    	User user = new User(getUsername(req));
	    	//use class name for grouping (detection point id)
	    	DetectionPoint detectionPoint = new DetectionPoint("Exception Handling", re.getMessage());
	    	Event event = new Event(user, detectionPoint, getDetectionSystem());
	    	KeyValuePair metadata = new KeyValuePair("exception.content", ExceptionUtils.getStackTrace(re));
	    	event.setMetadata(Arrays.asList(metadata));
	    	ids.addEvent(event);
		}
		
		return 0;
	}
	
	@RequestMapping(value = "api/list", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Event> generateException(HttpServletRequest req) {
		Collection<Event> events = ExceptionCache.findAll();
		
		return events;
	}
	
	@RequestMapping("foo")
	public String foo() {
		throw new RuntimeException("Expected foo exception in controller");
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