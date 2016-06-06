package org.owasp.appsensor.ui.handler;

import java.util.Collection;

import org.springframework.core.NamedThreadLocal;

public class AssociatedApplicationsContext {

	private static final ThreadLocal<Collection<String>> clientApplicationsHolder = new NamedThreadLocal<Collection<String>>("Associated Client Applications");
	
	public static void set(Collection<String> clientApplications) {
		clientApplicationsHolder.set(clientApplications);
	}
	
	public static Collection<String> get() {
		return clientApplicationsHolder.get();
	}
	
	public static void clear() {
		clientApplicationsHolder.set(null);
	}
	
}
