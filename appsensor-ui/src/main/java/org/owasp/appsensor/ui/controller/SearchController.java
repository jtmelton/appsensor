package org.owasp.appsensor.ui.controller;

import java.util.Collection;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.ui.rest.RestReportingEngineFacade;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class SearchController {
	
	@Autowired
	private RestReportingEngineFacade facade;
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/events", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Event> findEvents(@RequestParam("earliest") String rfc3339Timestamp) {
		return facade.findEvents(rfc3339Timestamp);
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/attacks", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Attack> findAttacks(@RequestParam("earliest") String rfc3339Timestamp) {
		return facade.findAttacks(rfc3339Timestamp);
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/responses", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Response> findResponses(@RequestParam("earliest") String rfc3339Timestamp) {
		return facade.findResponses(rfc3339Timestamp);
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/events/count", method = RequestMethod.GET)
	@ResponseBody
	public int countEvents(@RequestParam("earliest") String rfc3339Timestamp) {
		return facade.countEvents(rfc3339Timestamp);
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/attacks/count", method = RequestMethod.GET)
	@ResponseBody
	public int countAttacks(@RequestParam("earliest") String rfc3339Timestamp) {
		return facade.countAttacks(rfc3339Timestamp);
	}
	
	@PreAuthorize("hasAnyRole('VIEW_DATA')")
	@RequestMapping(value="/api/responses/count", method = RequestMethod.GET)
	@ResponseBody
	public int countResponses(@RequestParam("earliest") String rfc3339Timestamp) {
		return facade.countResponses(rfc3339Timestamp);
	}
	
}
