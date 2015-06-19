package org.owasp.appsensor.ui.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping("/geo-map")
public class GeoMapController {

	@RequestMapping(method = RequestMethod.GET)
	public String home() {
		return "geo-map";
	}

}
