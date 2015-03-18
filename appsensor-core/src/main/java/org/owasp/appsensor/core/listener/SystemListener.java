package org.owasp.appsensor.core.listener;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.storage.AttackStoreListener;
import org.owasp.appsensor.core.storage.EventStoreListener;
import org.owasp.appsensor.core.storage.ResponseStoreListener;

/**
 * This is a base class extended by classes that want to be notified
 * when a new {@link Event}, {@link Attack}, or {@link Response} is 
 * created and stored in the AppSensor system.
 * 
 * It is a convenience class that simplifies the notification mechanism, 
 * and will be used by classes such as emitters to external systems 
 * for integration.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * 
 * @since 2.1
 */
@EventStoreListener
@AttackStoreListener
@ResponseStoreListener
public abstract class SystemListener implements EventListener, AttackListener, ResponseListener {

}
