package org.owasp.appsensor.integration.springsecurity.response;

import java.util.Collection;
import javax.inject.Inject;
import javax.inject.Named;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.response.UserManager;
import org.slf4j.Logger;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.UserDetailsManager;

/**
 * This is an adapter for Spring Security to do user management actions
 * as part of the response
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
// primary - use this when on classpath (overrides other user manager impls
@Primary
@Named
@Loggable
public class SpringSecurityUserManager extends GlobalAuthenticationConfigurerAdapter implements
    UserManager {

    private Logger logger;

    @Inject
    private UserResponseCache userResponseCache;

    private UserDetailsManager userDetailsManager;

    @Override
    public void init(AuthenticationManagerBuilder auth) {
        if (auth != null &&
            auth.getDefaultUserDetailsService() != null &&
            auth.getDefaultUserDetailsService() instanceof UserDetailsManager) {
            userDetailsManager = (UserDetailsManager) auth.getDefaultUserDetailsService();
        } else {
            throw new IllegalStateException("UserDetailsManager could not be constructed properly");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void logout(User appSensorUser) {
        logger.info("Request received to logout user <{}>.", appSensorUser.getUsername());

        userResponseCache.setUserLoggedOut(appSensorUser.getUsername());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void disable(User appSensorUser) {
        logger.info("Request received to disable user <{}>.", appSensorUser.getUsername());

        if (userDetailsManager == null) {
            logger.warn("Could not disable user [" + appSensorUser.getUsername()
                        + "] since the spring security " +
                        "UserDetailsManager is not properly configured.");
            return;
        }

        UserDetails springUser = userDetailsManager.loadUserByUsername(appSensorUser.getUsername());

        if (springUser == null) {
            logger.warn("Could not disable user [" + appSensorUser.getUsername()
                        + "] because the user could not " +
                        "be found by lookup");
            return;
        }

        logger.info("Disabling user <{}>.", springUser.getUsername());
        userDetailsManager.updateUser(new DisabledUser(springUser));

        logger.info("After disabling user <{}>, also logging out so the disable gets triggered.",
            springUser.getUsername());
        userResponseCache.setUserLoggedOut(appSensorUser.getUsername());
    }

    /**
     * Simple shim helper class to represent disabled user.
     * Delegate all methods except for #isEnabled
     *
     * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
     */
    public static class DisabledUser implements UserDetails {

        private static final long serialVersionUID = 9173900190245012681L;

        private UserDetails delegate;

        public DisabledUser(UserDetails userDetails) {
            this.delegate = userDetails;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return delegate.getAuthorities();
        }

        @Override
        public String getPassword() {
            return delegate.getPassword();
        }

        @Override
        public String getUsername() {
            return delegate.getUsername();
        }

        @Override
        public boolean isAccountNonExpired() {
            return delegate.isAccountNonExpired();
        }

        @Override
        public boolean isAccountNonLocked() {
            return delegate.isAccountNonLocked();
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return delegate.isCredentialsNonExpired();
        }

        @Override
        public boolean isEnabled() {
            // override this one specifically - we are disabling the user
            return false;
        }

    }

}
