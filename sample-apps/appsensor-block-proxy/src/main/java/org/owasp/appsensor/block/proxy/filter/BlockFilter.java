package org.owasp.appsensor.block.proxy.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.appsensor.block.proxy.domain.BlockCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BlockFilter implements javax.servlet.Filter {
	
	private final static Logger LOGGER = LoggerFactory.getLogger(BlockFilter.class);

	private final BlockCache blockCache = BlockCache.get();
	
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        if (req instanceof HttpServletRequest && res instanceof HttpServletResponse) {
        	
        	HttpServletRequest request = (HttpServletRequest)req;
        	HttpServletResponse response = (HttpServletResponse)res;
        	
        	String ipAddress = findIp(request);
        	String resource = request.getRequestURI().toString();
        	
        	LOGGER.debug("checking if {} is blocked.", resource);
        	
        	boolean blocked = blockCache.isBlocked(ipAddress, resource);
        	
            if (! blocked) {
                chain.doFilter(req, res); 
            } else {
                HttpServletResponse httpResponse = (HttpServletResponse) response;
                httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
                httpResponse.getWriter().print("Access Blocked");
            }
        }
    }
    
    private String findIp(HttpServletRequest request) {
		// is client behind something?
		String ipAddress = request.getHeader("X-FORWARDED-FOR");
		
		if (ipAddress == null) {
			ipAddress = request.getRemoteAddr();
		}
		
		return ipAddress;
    }

	@Override
	public void destroy() { 
		//
	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {
		//
	}
}