package org.owasp.appsensor.ui.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping("/configuration")
public class ConfigurationController {

	@RequestMapping(method = RequestMethod.GET)
	public String home() {
		return "configuration";
	}

}
