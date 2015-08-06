package org.owasp.appsensor.ui.controller;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class ViewsController {
	
	private static final String DETECTION_POINT_LABEL_DETAIL = "DETECTION_POINT_LABEL_DETAIL";
	private static final String USERNAME_DETAIL = "USERNAME_DETAIL";
	
	@RequestMapping(value="/about", method = RequestMethod.GET)
	public String about() {
		return "about";
	}
	
	@RequestMapping(value="/configuration", method = RequestMethod.GET)
	public String configuration() {
		return "configuration";
	}
	
	@RequestMapping(value="/", method = RequestMethod.GET)
	public String dashboard() {
		return "dashboard";
	}
	
	@RequestMapping(value="/detection-points/{label}", method = RequestMethod.GET)
	public String detectionPoint(@PathVariable String label, Map<String, Object> model) {
		model.put(DETECTION_POINT_LABEL_DETAIL, label);
		return "detection-point";
	}
	
	@RequestMapping(value="/users/{username}", method = RequestMethod.GET)
	public String user(@PathVariable String username, Map<String, Object> model) {
		model.put(USERNAME_DETAIL, username);
		return "user";
	}
	
	@RequestMapping(value="/geo-map", method = RequestMethod.GET)
	public String geoMap() {
		return "geo-map";
	}
	
	@RequestMapping(value="/trends-dashboard", method = RequestMethod.GET)
	public String trendsDashboard() {
		return "trends-dashboard";
	}
	
	@RequestMapping(value="/ping", method = RequestMethod.GET)
	@ResponseBody
	public boolean keepalive() {
		return true;
	}
	
	@RequestMapping("/login")
	public String login(Map<String, Object> model, HttpServletRequest request) {
		CsrfToken token = (CsrfToken) request.getAttribute("_csrf");
		
		model.put("csrfTokenName", token.getParameterName());
		model.put("csrfTokenValue", token.getToken());

		parameterToModel("error", model, request);
		parameterToModel("logout", model, request);
		
		return "login";
	}

	private void parameterToModel(String name, Map<String, Object> model, HttpServletRequest request) {
		if(request.getParameter(name) != null) {
			model.put(name, name);
		}
	}
	
}
