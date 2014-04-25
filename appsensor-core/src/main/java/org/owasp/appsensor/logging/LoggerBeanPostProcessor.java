package org.owasp.appsensor.logging;

import java.lang.reflect.Field;

import javax.inject.Named;

import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;

@Named
public class LoggerBeanPostProcessor implements BeanPostProcessor {

	@Override
	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		
		//if "logger" field does not exist, exception simply logged
		if(bean.getClass().isAnnotationPresent(Loggable.class)){
            try {
                Field field = bean.getClass().getDeclaredField("logger");
                field.setAccessible(true);
                field.set(bean, LoggerFactory.getLogger(bean.getClass()));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
		
		return bean;
	}

	@Override
	public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}
}