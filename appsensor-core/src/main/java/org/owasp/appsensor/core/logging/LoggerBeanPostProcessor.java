package org.owasp.appsensor.core.logging;

import java.lang.reflect.Field;

import javax.inject.Named;

import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;

/**
 * This class is a Spring post-processor to use reflection to set
 * the logger fields of all classes marked as {@link Loggable}. 
 * The logger is marked with the appropriate class. This prevents us 
 * from having to set the class for the logger in each individual class.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
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
            	System.err.println("Error processing logger for " + bean.getClass().getCanonicalName() + " for bean " + beanName);
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