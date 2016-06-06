package org.owasp.appsensor.ui.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

@Component
public class ContextPathInterceptor extends HandlerInterceptorAdapter {

    /**
     * The attribute to write to
     */
    public static final String CONTEXT_PATH = "CONTEXT_PATH";

    @Override
    public void postHandle(final HttpServletRequest request,
            final HttpServletResponse response, final Object handler,
            final ModelAndView modelAndView) throws Exception {
    	
    	String contextPath = "";
    	if (request.getSession(false) != null) {
			contextPath = request.getContextPath();
    	}
    	
        if (modelAndView != null) {
            modelAndView.getModelMap().addAttribute(CONTEXT_PATH, contextPath);
        }
        
    }
    
}