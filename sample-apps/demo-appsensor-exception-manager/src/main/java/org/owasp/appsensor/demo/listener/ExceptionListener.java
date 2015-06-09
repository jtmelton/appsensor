package org.owasp.appsensor.demo.listener;

import javax.inject.Named;

import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.listener.EventListener;
import org.owasp.appsensor.core.storage.EventStoreListener;
import org.owasp.appsensor.demo.ExceptionCache;

@Named
@EventStoreListener
public class ExceptionListener implements EventListener {

	@Override
	public void onAdd(Event event) {
		ExceptionCache.save(event);
	}

}
