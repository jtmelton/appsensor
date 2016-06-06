package org.owasp.appsensor.ui.handler;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class AssociatedApplicationsFilter implements Filter {
	
	private Logger LOGGER = LoggerFactory.getLogger(this.getClass());
	
	@SuppressWarnings("unchecked")
	@Override
	public void doFilter(ServletRequest req, ServletResponse response, FilterChain chain) throws IOException {
	    try {
	    	HttpServletRequest request = (HttpServletRequest)req;
	    	if(request != null && request.getSession(false) != null) {
	    		AssociatedApplicationsContext.set((Collection<String>)request.getSession(false).getAttribute(AssociatedClientApplicationsAuthenticationSuccessHandler.ASSOCIATED_CLIENT_APPLICATIONS));
	    	}
            chain.doFilter(request, response);
	    } catch (Exception e) {
	    	LOGGER.error("Error setting associated applications.", e );
	    } finally {
	    	AssociatedApplicationsContext.clear();
	    }
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException { }

	@Override
	public void destroy() { }
	
}
