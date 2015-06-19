package org.owasp.appsensor.ui.controller;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class LoginController {

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
