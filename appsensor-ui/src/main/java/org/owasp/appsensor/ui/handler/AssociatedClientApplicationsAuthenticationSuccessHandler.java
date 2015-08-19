package org.owasp.appsensor.ui.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.appsensor.ui.entity.User;
import org.owasp.appsensor.ui.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class AssociatedClientApplicationsAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
	
	public static final String ASSOCIATED_CLIENT_APPLICATIONS = "ASSOCIATED_CLIENT_APPLICATIONS";
	
	private Logger LOGGER = LoggerFactory.getLogger(this.getClass());
	
	@Autowired
	private UserRepository userRepository;
	
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
            HttpServletResponse response, Authentication authentication)
            throws ServletException, IOException {
    	
    	User user = userRepository.findByUsername(authentication.getName());
    	LOGGER.info("Successful authentication for user: {}", user);
    	
    	// put the associated client applications on the session
    	request.getSession(false).setAttribute(ASSOCIATED_CLIENT_APPLICATIONS, user.getClientApplications());
    	
        super.onAuthenticationSuccess(request, response, authentication);
    }
    
}