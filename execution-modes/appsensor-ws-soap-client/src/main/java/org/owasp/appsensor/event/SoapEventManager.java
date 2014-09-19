package org.owasp.appsensor.event;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Service;
import javax.xml.ws.handler.Handler;

import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.event.EventManager;
import org.owasp.appsensor.core.util.DateUtils;
import org.owasp.appsensor.handler.RegisterClientApplicationIdentificationHandler;
import org.owasp.appsensor.handler.SoapRequestHandler;
import org.springframework.remoting.jaxws.JaxWsPortProxyFactoryBean;

/**
 * This event manager should perform soap style requests since it functions
 * as the reference soap client.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Named
public class SoapEventManager implements EventManager {

	private SoapRequestHandler soapService;
	
	@Inject
	private AppSensorClient appSensorClient;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) {
		initializeService();
		
		soapService.addEvent(event);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		initializeService();
		
		soapService.addAttack(attack);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> getResponses() {
		initializeService();
		
		Collection<Response> responses = soapService.getResponses(DateUtils.getCurrentTimestamp().minusHours(10).toString());
		return responses;
	}
	
	private void initializeService() {
		if(soapService == null) {
			String url = appSensorClient.getConfiguration().getServerConnection().getUrl();
			
			try {
				JaxWsPortProxyFactoryBean proxy = new JaxWsPortProxyFactoryBean();
				
				proxy.setServiceInterface(org.owasp.appsensor.handler.SoapRequestHandler.class);
				proxy.setWsdlDocumentUrl(new URL(url + "?wsdl"));
				proxy.setNamespaceUri("https://www.owasp.org/index.php/OWASP_AppSensor_Project/wsdl");
				proxy.setServiceName("SoapRequestHandlerService");
				proxy.setEndpointAddress(url);
				
				Service result = proxy.createJaxWsService();
				
				soapService = result.getPort(SoapRequestHandler.class);
			} catch (MalformedURLException e) {
				e.printStackTrace();
			}
		}
		
		bindHeaders();
	}
	
	@SuppressWarnings("rawtypes")
	private void bindHeaders() {
		Binding binding = ((BindingProvider) soapService).getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		if (handlerChain == null) {
			handlerChain = new ArrayList<Handler>();
		}
		
		RegisterClientApplicationIdentificationHandler handler = new RegisterClientApplicationIdentificationHandler();
		handler.setAppSensorClient(appSensorClient);

		handlerChain.add(handler);
		binding.setHandlerChain(handlerChain);
	}
	
}
