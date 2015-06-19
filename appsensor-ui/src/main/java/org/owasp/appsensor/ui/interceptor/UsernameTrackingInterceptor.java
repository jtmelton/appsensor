package org.owasp.appsensor.ui.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

@Component
public class UsernameTrackingInterceptor extends HandlerInterceptorAdapter {

    /**
     * The attribute to write to
     */
    public static final String LOGGED_IN_USERNAME = "LOGGED_IN_USERNAME";


    @Override
    public void postHandle(final HttpServletRequest request,
            final HttpServletResponse response, final Object handler,
            final ModelAndView modelAndView) throws Exception {
    	
    	String username = "";
    	if (request.getSession(false) != null) {
    		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    		if (authentication != null) {
    			String currentPrincipalName = authentication.getName();

    			username = currentPrincipalName;
    		}
    	}
    	
        if (modelAndView != null) {
            modelAndView.getModelMap().addAttribute(LOGGED_IN_USERNAME, username);
        }
        
    }
    
}