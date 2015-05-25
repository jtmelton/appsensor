package org.owasp.appsensor.demo.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthFilter implements Filter {

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// do nothing
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		
		//let login request through
		if (httpRequest.getServletPath().equals("/login")) {
			chain.doFilter(request, response);
		} else {
			if (httpRequest.getSession().getAttribute("LOGGED_IN_USER") == null) {
				httpResponse.sendRedirect("/login");
			} else {
			    chain.doFilter(request, response);
			}
		}
	}

	@Override
	public void destroy() {
		// do nothing
	}

}
