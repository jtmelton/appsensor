package org.owasp.appsensor.rpc.thrift;

import java.net.InetAddress;

import javax.inject.Inject;
import javax.inject.Named;

import org.apache.thrift.server.TServer;
import org.apache.thrift.server.TThreadPoolServer;
import org.apache.thrift.transport.TSSLTransportFactory;
import org.apache.thrift.transport.TServerSocket;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.rpc.thrift.generated.AppSensorApi;
import org.slf4j.Logger;

import com.google.common.base.Strings;

@Named
@Loggable
public class AppSensorThriftSslServer {
	
	private Logger logger;
	
	@Inject
	private AppSensorApiHandler appSensorApiHandler;
	
	@Inject
	private AppSensorServer appSensorServer;
	
	private TServer server;
	
	public void start() {
		logger.info("Starting the AppSensorThrift server...");
		
		ensureEnvironmentVariableExists("javax.net.ssl.keyStore");
		ensureEnvironmentVariableExists("javax.net.ssl.keyStorePassword");
		
		try {
			final AppSensorApi.Processor<AppSensorApiHandler> processor = new AppSensorApi.Processor<AppSensorApiHandler>(appSensorApiHandler);
 
            //use http://architects.dzone.com/articles/how-secure-and-apache-thrift
            TSSLTransportFactory.TSSLTransportParameters params =
                    new TSSLTransportFactory.TSSLTransportParameters();
            params.setKeyStore(System.getenv("javax.net.ssl.keyStore"), System.getenv("javax.net.ssl.keyStorePassword"));
            
            int port = appSensorServer.getConfiguration().getServerPort();
            int socketTimeout = appSensorServer.getConfiguration().getServerSocketTimeout();
            String serverName = appSensorServer.getConfiguration().getServerHostName();	
            
            final TServerSocket serverTransport = TSSLTransportFactory.getServerSocket(
            		port, socketTimeout, InetAddress.getByName(serverName), params);
            
            final TServer server = new TThreadPoolServer(new TThreadPoolServer.Args(serverTransport).processor(processor));
            server.serve();
            
			logger.info("Started the AppSensorThrift server.");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void ensureEnvironmentVariableExists(String variable) {
		if(Strings.isNullOrEmpty(System.getenv(variable))) {
    		throw new IllegalArgumentException("The environment variable '" + variable + "' must be set for appsensor-thrift to connect");
    	}
	}
	
	public void stop() {
		try {
			logger.info("Stopping the AppSensorThrift server...");
			
			if (server != null && server.isServing()) {
				server.stop();
			}
			
			logger.info("Stopped the AppSensorThrift server.");
		} catch (Exception e) {
			e.printStackTrace();
		}		
	}
	
}
