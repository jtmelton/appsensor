package org.owasp.appsensor.rpc.thrift;

import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class AppSensorApiServer {

	public static void main(String[] args) {
		
	    @SuppressWarnings("resource")
		AbstractApplicationContext context = new ClassPathXmlApplicationContext("applicationContext.xml");
	    AppSensorThriftSslServer server = context.getBean(AppSensorThriftSslServer.class);
		
		server.start();
	}
	
}
