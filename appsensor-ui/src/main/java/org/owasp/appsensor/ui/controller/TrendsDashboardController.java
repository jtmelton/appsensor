package org.owasp.appsensor.ui.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class TrendsDashboardController {

	@RequestMapping(value="/trends-dashboard", method = RequestMethod.GET)
	public String home() {
		return "trends-dashboard";
	}

}
