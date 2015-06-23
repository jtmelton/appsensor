package org.owasp.appsensor.ui.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

@Component
public class PathTrackingInterceptor extends HandlerInterceptorAdapter {

    /**
     * The attribute to write to
     */
    public static final String ACTIVE_PATH = "ACTIVE_PATH";


    @Override
    public void postHandle(final HttpServletRequest request,
            final HttpServletResponse response, final Object handler,
            final ModelAndView modelAndView) throws Exception {
    	
    	String path = "";
    	
    	if (request.getSession(false) != null) {
    		String servletPath = request.getServletPath();
    		
    		if (servletPath != null) {
    			if (servletPath.contains("/")) {
    				path = servletPath.substring(servletPath.lastIndexOf("/") + 1, servletPath.length());
    			} else {
    				path = servletPath;
    			}
    			
    			//special handler for dashboard
    			if ("".equals(path.trim())) {
    				path = "dashboard";
    			}
    			
    		}
    	}
    	
        if (modelAndView != null) {
            modelAndView.getModelMap().addAttribute(ACTIVE_PATH + "_" + path, path);
        }
        
    }
    
}