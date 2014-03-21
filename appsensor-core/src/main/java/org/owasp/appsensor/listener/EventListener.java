package org.owasp.appsensor.listener;

import org.owasp.appsensor.Event;

public interface EventListener {
	public void onAdd(Event event);
}
