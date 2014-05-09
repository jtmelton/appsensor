package org.owasp.appsensor.storage;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import javax.inject.Qualifier;

import org.owasp.appsensor.Response;

/**
 * Annotation for Listener for {@link ResponseStore}. If applied 
 * to a class, then it is registered as a listener and notified 
 * if a new {@link Response} is added to the {@link ResponseStore}.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Qualifier
@Retention(RUNTIME)
@Target({TYPE, METHOD, FIELD, PARAMETER})
@Inherited
public @interface ResponseStoreListener {

}
