package org.owasp.appsensor.ui.interceptor;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
public class InterceptorConfigurerAdapter extends WebMvcConfigurerAdapter {

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(new UsernameTrackingInterceptor()).addPathPatterns("/**");
        registry.addInterceptor(new ContextPathInterceptor()).addPathPatterns("/**");
        registry.addInterceptor(new PathTrackingInterceptor()).addPathPatterns("/**");
    }

}