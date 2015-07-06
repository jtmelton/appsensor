package org.owasp.appsensor.ui.controller;

import java.util.Collection;

import javax.ws.rs.QueryParam;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.ui.rest.RestReportingEngineFacade;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class SearchController {
	
	@Autowired
	private RestReportingEngineFacade facade;
	
	@RequestMapping(value="/api/events", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Event> findEvents(@QueryParam("earliest") String rfc3339Timestamp) {
		return facade.findEvents(rfc3339Timestamp);
	}
	
	@RequestMapping(value="/api/attacks", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Attack> findAttacks(@QueryParam("earliest") String rfc3339Timestamp) {
		return facade.findAttacks(rfc3339Timestamp);
	}
	
	@RequestMapping(value="/api/responses", method = RequestMethod.GET)
	@ResponseBody
	public Collection<Response> findResponses(@QueryParam("earliest") String rfc3339Timestamp) {
		return facade.findResponses(rfc3339Timestamp);
	}
	
	@RequestMapping(value="/api/events/count", method = RequestMethod.GET)
	@ResponseBody
	public int countEvents(@QueryParam("earliest") String rfc3339Timestamp) {
		return facade.countEvents(rfc3339Timestamp);
	}
	
	@RequestMapping(value="/api/attacks/count", method = RequestMethod.GET)
	@ResponseBody
	public int countAttacks(@QueryParam("earliest") String rfc3339Timestamp) {
		return facade.countAttacks(rfc3339Timestamp);
	}
	
	@RequestMapping(value="/api/responses/count", method = RequestMethod.GET)
	@ResponseBody
	public int countResponses(@QueryParam("earliest") String rfc3339Timestamp) {
		return facade.countResponses(rfc3339Timestamp);
	}
	
}
