package org.owasp.appsensor.integration.springsecurity.event;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;

import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.DetectionPoint.Category;
import org.owasp.appsensor.core.DetectionSystem;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.IPAddress;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.event.EventManager;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * This is an event listener for Spring Security events that will see those 
 * events and re-send them to the {@link EventManager}.
 * 
 * This relies on the Spring event handling mechanism, and specifically 
 * on the events that Spring Security emits. 
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class SpringSecurityEventListener implements ApplicationListener<ApplicationEvent> {
 
	@Inject
	private transient IPAddress locator;
	
	@Inject 
	private AppSensorClient appSensorClient;
	
	@Inject 
	private EventManager ids;
	
	private static String cachedIp = null;
	
    @Override
    public void onApplicationEvent(ApplicationEvent applicationEvent) {
 
		// process event
		if (applicationEvent instanceof AbstractAuthenticationFailureEvent) {
			
			AbstractAuthenticationFailureEvent event = (AbstractAuthenticationFailureEvent)applicationEvent;
			
			IPAddress userAddress = getUserIp(event.getAuthentication());
			
			// if we fail authentication and can't get the IP, just skip this event
			if (userAddress == null) {
				return;
			}
			
			User user = new User(userAddress.getAddressAsString(), userAddress);
			// AE3: High Rate of Login Attempts
			DetectionPoint detectionPoint = new DetectionPoint(Category.AUTHENTICATION, "AE3");
			ids.addEvent(new Event(user, detectionPoint, getDetectionSystem()));
			
		} else if (applicationEvent instanceof AuthenticationSuccessEvent || applicationEvent instanceof InteractiveAuthenticationSuccessEvent) {
			
			// STE2: High Number of Logins Across The Site
			AbstractAuthenticationEvent event = (AbstractAuthenticationEvent)applicationEvent;
			
			Authentication authentication = event.getAuthentication();
			IPAddress userAddress = getUserIp(authentication);
			
			User user = new User(getUserName(authentication), userAddress);
			// AE3: High Rate of Login Attempts
			DetectionPoint detectionPoint = new DetectionPoint(Category.SYSTEM_TREND, "STE2");
			ids.addEvent(new Event(user, detectionPoint, getDetectionSystem()));
			
		} else if (applicationEvent instanceof SessionDestroyedEvent) {
			
			SessionDestroyedEvent event = (SessionDestroyedEvent)applicationEvent;
			
			List<SecurityContext> securityContexts = event.getSecurityContexts();
			if(securityContexts == null || securityContexts.size() == 0) {
				// if there are no destroyed contexts, ignore
				return;
			}
			
			Collection<String> userNamesSeen = new HashSet<>();
			
			// get first context
	        for (SecurityContext securityContext : securityContexts) {
	        	
	        	Authentication authentication = securityContext.getAuthentication();
				IPAddress userAddress = getUserIp(authentication);
				
				String userName = getUserName(authentication);
				
				if(userNamesSeen.contains(userName)) {
	        		// if we've already created the event for this user, skip
					continue;
	        	}
				
				User user = new User(userName, userAddress);
				// STE1: High Number of Logouts Across The Site
				DetectionPoint detectionPoint = new DetectionPoint(Category.SYSTEM_TREND, "STE1");
				ids.addEvent(new Event(user, detectionPoint, getDetectionSystem()));
				
				userNamesSeen.add(userName);
	        }
	     
	        
		}
    }
    
    private IPAddress getUserIp(Authentication authentication) {
    	if (authentication.getDetails() instanceof WebAuthenticationDetails) {
			return null;
		}

		// retrieve IP address for failure
		WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
		String remoteAddress = details.getRemoteAddress();
		
		if(remoteAddress == null) {
			return null;
		}
		
		return locator.fromString(remoteAddress);
    }
    
    private String getUserName(Authentication authentication) {
    	String userName = authentication.getName();
    	
    	// overwrite if we can be more specific
    	if (authentication instanceof UserDetails) {
    		UserDetails userDetails = (UserDetails)authentication;
    		
    		userName = userDetails.getUsername();
    	}
		
		return userName;
    }
    
    private DetectionSystem getDetectionSystem() {
    	return new DetectionSystem(
    			appSensorClient.getConfiguration().getServerConnection().getClientApplicationIdentificationHeaderValue(), 
    			locator.fromString(getApplicationIp()));
    }
    
    private String getApplicationIp() {
    	if (cachedIp != null) {
    		return cachedIp;
    	}
    	
    	String ip = null;
    	
        try {
        	
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                // filters out 127.0.0.1 and inactive interfaces
                if (iface.isLoopback() || !iface.isUp()) {
                    continue;
                }

                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                
                while(addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    ip = addr.getHostAddress();
                    cachedIp = ip;
                }
            }
            
        } catch (SocketException e) {
            // ignore this exception
        }
        
        return ip;
    }
    
}