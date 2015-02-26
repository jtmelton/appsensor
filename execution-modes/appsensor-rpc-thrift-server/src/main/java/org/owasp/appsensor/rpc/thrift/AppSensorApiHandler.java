package org.owasp.appsensor.rpc.thrift;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;

import org.apache.thrift.TException;
import org.dozer.DozerBeanMapperSingletonWrapper;
import org.dozer.Mapper;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.ClientApplication;
import org.owasp.appsensor.core.DetectionSystem;
import org.owasp.appsensor.core.accesscontrol.Action;
import org.owasp.appsensor.core.accesscontrol.Context;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.util.StringUtils;
import org.owasp.appsensor.rpc.thrift.generated.AppSensorApi;
import org.owasp.appsensor.rpc.thrift.generated.Attack;
import org.owasp.appsensor.rpc.thrift.generated.Event;
import org.owasp.appsensor.rpc.thrift.generated.NotAuthenticatedException;
import org.owasp.appsensor.rpc.thrift.generated.NotAuthorizedException;
import org.owasp.appsensor.rpc.thrift.generated.Response;
import org.slf4j.Logger;

import com.google.common.base.Strings;

@Named
@Loggable
public class AppSensorApiHandler implements AppSensorApi.Iface {

	private Logger logger;

	@Inject 
	private AppSensorServer appSensorServer;

	private Mapper mapper = DozerBeanMapperSingletonWrapper.getInstance();
	
	@Override
	public void addEvent(Event event, String clientApplicationName)
			throws NotAuthenticatedException, NotAuthorizedException,
			TException {
		authenticateAndAuthorize(clientApplicationName, Action.ADD_EVENT);
		
		try {
			org.owasp.appsensor.core.Event appSensorEvent = mapper.map(event, org.owasp.appsensor.core.Event.class);
			
			appSensorEvent.setDetectionSystem(new DetectionSystem(clientApplicationName));
			
			appSensorServer.getEventStore().addEvent(appSensorEvent);
		} catch (Exception e) {
			logger.error("Could not complete event add.", e);
		}
		
	}

	@Override
	public void addAttack(Attack attack, String clientApplicationName)
			throws NotAuthenticatedException, NotAuthorizedException,
			TException {
		authenticateAndAuthorize(clientApplicationName, Action.ADD_ATTACK);
		
		try {
			org.owasp.appsensor.core.Attack appSensorAttack = mapper.map(attack, org.owasp.appsensor.core.Attack.class);
			
			appSensorAttack.setDetectionSystem(new DetectionSystem(clientApplicationName));
			
			appSensorServer.getAttackStore().addAttack(appSensorAttack);
		} catch (Exception e) {
			logger.error("Could not complete attack add.", e);
		}
	}

	@Override
	public List<Response> getResponses(String earliest, String clientApplicationName)
			throws NotAuthenticatedException, NotAuthorizedException,
			TException {
		authenticateAndAuthorize(clientApplicationName, Action.GET_RESPONSES);
		
		SearchCriteria criteria = new SearchCriteria().
				setDetectionSystemIds(StringUtils.toCollection(clientApplicationName))
				.setEarliest(earliest);

		Collection<org.owasp.appsensor.core.Response> appSensorResponses = appSensorServer.getResponseStore().findResponses(criteria);
		
		List<Response> responses = new ArrayList<Response>();
		
		for(org.owasp.appsensor.core.Response appSensorResponse : appSensorResponses) {
			
			try {
				Response response = mapper.map(appSensorResponse, org.owasp.appsensor.rpc.thrift.generated.Response.class);
				
				responses.add(response);
			} catch (Exception e) {
				logger.error("Could not complete response get.", e);
			}
		}
		
		return responses;
	}
	
	protected void authenticateAndAuthorize(String clientApplicationName, Action action) throws NotAuthenticatedException, NotAuthorizedException {
		
		if(Strings.isNullOrEmpty(clientApplicationName)) {
			String authenticationFailureMessage = "You must submit a client application name with the request.";
			logger.warn("Authentication for client application failed with message: " + authenticationFailureMessage);
			throw new NotAuthenticatedException(authenticationFailureMessage);
		}

		ClientApplication clientApplication = appSensorServer.getConfiguration().findClientApplication(clientApplicationName);
		
		if(clientApplication == null) {
			String authenticationFailureMessage = "Submitted client application name is not valid for this server.";
			logger.warn("Authentication for client application failed with message: " + authenticationFailureMessage);
			throw new NotAuthenticatedException(authenticationFailureMessage);
		}
		
		try {
			appSensorServer.getAccessController().assertAuthorized(clientApplication, action, new Context());
		} catch(Exception e) {
			
		}
	}

}
