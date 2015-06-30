package org.owasp.appsensor.ui.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class DashboardController {

	@RequestMapping(value="/", method = RequestMethod.GET)
	public String home() {
		return "dashboard";
	}
	
	@RequestMapping(value="/ping", method = RequestMethod.GET)
	@ResponseBody
	public boolean keepalive() {
		return true;
	}

}
