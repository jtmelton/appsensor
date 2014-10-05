package org.owasp.appsensor.rpc.thrift;

import java.util.ArrayList;
import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;

import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.TSSLTransportFactory;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;
import org.dozer.DozerBeanMapperSingletonWrapper;
import org.dozer.Mapper;
import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.event.EventManager;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.rpc.thrift.generated.AppSensorApi;
import org.slf4j.Logger;

import com.google.common.base.Strings;

@Named
@Loggable
public class ThriftEventManager implements EventManager {

	private Logger logger;
	
	@Inject
	private AppSensorClient appSensorClient;
	
	private String host;
	private String clientApplicationName;
	private Integer port;
	private Integer socketTimeout;
	
	private Mapper mapper = DozerBeanMapperSingletonWrapper.getInstance();
	
	@Override
	public void addEvent(Event event) {
		TTransport transport = getTransport();
		final TProtocol protocol = new TBinaryProtocol(transport);
		final AppSensorApi.Client client = new AppSensorApi.Client(protocol);

		//All hooked up, start using the service
		try {
			org.owasp.appsensor.rpc.thrift.generated.Event thriftEvent = mapper.map(event, org.owasp.appsensor.rpc.thrift.generated.Event.class);
			
			client.addEvent(thriftEvent, clientApplicationName);
			
			transport.close();
		} catch(Exception e) {
			logger.error("Could not complete event add.", e);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		TTransport transport = getTransport();
		final TProtocol protocol = new TBinaryProtocol(transport);
		final AppSensorApi.Client client = new AppSensorApi.Client(protocol);

		//All hooked up, start using the service
		try {
			org.owasp.appsensor.rpc.thrift.generated.Attack thriftAttack = mapper.map(attack, org.owasp.appsensor.rpc.thrift.generated.Attack.class);
			
			client.addAttack(thriftAttack, clientApplicationName);
			
			transport.close();
		} catch(Exception e) {
			logger.error("Could not complete event add.", e);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> getResponses(String earliest) {
		Collection<Response> responses = new ArrayList<>();
		
		TTransport transport = getTransport();
		final TProtocol protocol = new TBinaryProtocol(transport);
		final AppSensorApi.Client client = new AppSensorApi.Client(protocol);

		//All hooked up, start using the service
		try {
			Collection<org.owasp.appsensor.rpc.thrift.generated.Response> thriftResponses = client.getResponses(earliest, clientApplicationName);
			
			for (org.owasp.appsensor.rpc.thrift.generated.Response thriftResponse : thriftResponses) {
				 
				Response response = mapper.map(thriftResponse, Response.class);
				
				responses.add(response);
			}
			
			transport.close();
		} catch(Exception e) {
			logger.error("Could not complete event add.", e);
		}
		
		return responses;
	}
	
	public TTransport getTransport() {
		ensureEnvironmentVariableExists("javax.net.ssl.trustStore");
		ensureEnvironmentVariableExists("javax.net.ssl.trustStorePassword");
    	
		if (host == null) {
			host = appSensorClient.getConfiguration().getServerConnection().getUrl();
		}
		
		if (clientApplicationName == null) {
			clientApplicationName = appSensorClient.getConfiguration().getServerConnection().getClientApplicationIdentificationHeaderValue();
		}
		
		if (port == null) {
			port = appSensorClient.getConfiguration().getServerConnection().getPort();
		}
		
		if (socketTimeout == null) {
			socketTimeout = appSensorClient.getConfiguration().getServerConnection().getSocketTimeout();
		}
		
		//Setup the transport and protocol
		final TSocket socket = new TSocket(host, port);
		socket.setTimeout(socketTimeout);
		
		TTransport transport = null;

        try {
    		TSSLTransportFactory.TSSLTransportParameters params =
                  new TSSLTransportFactory.TSSLTransportParameters();
    		params.setTrustStore(System.getenv("javax.net.ssl.trustStore"), System.getenv("javax.net.ssl.trustStorePassword"));

            transport = TSSLTransportFactory.getClientSocket(host, port, socketTimeout, params);
		} catch (TTransportException e) {
			logger.error("Failure to produce secure thrift client socket", e);
		}
		
		return transport;
	}
	
	private void ensureEnvironmentVariableExists(String variable) {
		if(Strings.isNullOrEmpty(System.getenv(variable))) {
    		throw new IllegalArgumentException("The environment variable '" + variable + "' must be set for appsensor-thrift to connect");
    	}
	}
	
}
