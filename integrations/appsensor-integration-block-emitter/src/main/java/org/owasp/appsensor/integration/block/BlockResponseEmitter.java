package org.owasp.appsensor.integration.block;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;

import org.apache.commons.lang3.StringUtils;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.ResponseListener;
import org.owasp.appsensor.core.storage.AttackStore;
import org.owasp.appsensor.core.storage.ResponseStoreListener;
import org.owasp.appsensor.integration.block.domain.BlockRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import com.google.gson.Gson;

/**
 * This is the Influxdb Emitter. 
 * 
 * It is notified whenever new {@link Event}, {@link Attack} 
 * or {@link Response} objects are added to the system. 
 * 
 * The implementation sends events/attacks/responses to 
 * influx every time they are received. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * 
 * @since 2.2
 * 
 */

/**
 * This is the Block Emitter. 
 * 
 * It is notified whenever new {@link Response} objects are added to the system. 
 * 
 * The implementation looks at the {@link Response} and decides if 
 * it is a "block" operation. If so, it attempts to resolve the IP address
 * of the user. If it can, then it notifies the "block store" component 
 * via a REST api. 
 * 
 * <p>Note: This class requires certain settings to run properly. This/these can be set as 
 *    environment variables ('export my_var="some_value"') or environment 
 *    properties ('-Dmy_var=some_value') set at the JVM</p>
 * <ul>
 *   <li><em>APPSENSOR_BLOCK_STORE_URL</em> - the url used to connect to the appsensor block store, e.g. "http://1.2.3.4:8090/api/v1.0/blocks"</li>
 * </ul>
 * 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * 
 * @since 2.2.1
 */
@Named
@ResponseStoreListener
public class BlockResponseEmitter implements ResponseListener {
	
	private boolean initializedProperly = false;
	
	public static final String BLOCK_STORE_URL = "APPSENSOR_BLOCK_STORE_URL";
	private static final String DISABLE_COMPONENT_FOR_ONE_USER = "disableComponentForSpecificUser";
	private static final String DISABLE_COMPONENT_FOR_ALL_USERS = "disableComponentForAllUsers";

	private Collection<String> disableResponseActions = Arrays.asList(DISABLE_COMPONENT_FOR_ONE_USER, DISABLE_COMPONENT_FOR_ALL_USERS);
	
	private String blockStoreUrl;
	
	private WebTarget target;
	
	private Gson gson = new Gson();
	
	private Logger logger = LoggerFactory.getLogger(getClass());
	
	@Inject
	private AttackStore attackStore;
	
	@Inject
	private Environment environment;
	
	public BlockResponseEmitter() {}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Response response) {
		ensureInitialized();

		// don't care about non-"disable" responses
		if(! disableResponseActions.contains(response.getAction())) {
			return;
		}
		
		Attack sourceAttack = findSourceAttack(response);
		
		//couldn't find matching attack - need it for "resource"
		if(sourceAttack == null) {
			logger.warn("Could not discover attack match for given response. "
					+ "This should not happen under normal circumstances. "
					+ "Response is: " + response);
			return;
		}
		
		if(response.getUser().getIPAddress() == null) {
			logger.debug("Ignoring block response - user IP unknown. "
					+ "Response is: " + response);
			return;
		}
		
		if(sourceAttack.getResource() == null || sourceAttack.getResource().getLocation() == null) {
			logger.debug("Ignoring block response - resource unknown. "
					+ "Response is: " + response);
			return;
		}
		
		BlockRequest blockRequest = new BlockRequest()
				.setIpAddress(response.getUser().getIPAddress().getAddressAsString())
				.setResource(sourceAttack.getResource().getLocation())
				.setMilliseconds(response.getInterval().toMillis());
		
		try {
			target.request(MediaType.APPLICATION_JSON)
	                .post(Entity.entity(gson.toJson(blockRequest), MediaType.APPLICATION_JSON));
			
			logger.info("Sent block request to block store. Request was to block: " + blockRequest);
		} catch(Exception e) {
			logger.error("Error sending block request to block store. ", e);
		}
	}
	
	private Attack findSourceAttack(Response response) {
		SearchCriteria criteria = new SearchCriteria()
			.setUser(response.getUser())
			.setDetectionSystemIds(Arrays.asList(response.getDetectionSystem().getDetectionSystemId()))
			.setEarliest(response.getTimestamp());

		Collection<Attack> attacks = attackStore.findAttacks(criteria);
		
		Attack sourceAttack = null;
		
		for(Attack attack : attacks) {
			if(attack.getTimestamp().equals(response.getTimestamp())) {
				// found match;
				sourceAttack = attack;
				break;
			}
		}
		
		return sourceAttack;
	}
	
	@PostConstruct
	public void ensureEnvironmentVariablesSet() {
		initializedProperly = isInitializedProperly();

		if (! initializedProperly) {
			logger.error(getUninitializedMessage());
		} else {
			initializeConfig();
			initializeRestClient();
		}
	}
	
	private void ensureInitialized() {
		if(! initializedProperly) {
			throw new IllegalStateException(getUninitializedMessage());
		}
	}
	
	private void initializeConfig() {
		blockStoreUrl = environment.getProperty(BLOCK_STORE_URL);
	}
	
	private void initializeRestClient() {
		target = ClientBuilder.newClient().target(blockStoreUrl);
	}
	
	private boolean isInitializedProperly() {
		boolean initializedProperly = false;
		
		initializedProperly = StringUtils.isNotBlank(environment.getProperty(BLOCK_STORE_URL));

		return initializedProperly;
	}
	
	private String getUninitializedMessage() {
		StringBuilder sb = new StringBuilder();
		
		Collection<String> setVariables = new ArrayList<>();
		Collection<String> missingVariables = new ArrayList<>();
		
		if (StringUtils.isBlank(environment.getProperty(BLOCK_STORE_URL))) {
			missingVariables.add(BLOCK_STORE_URL);
		} else {
			setVariables.add(BLOCK_STORE_URL);
		}
		
		if (missingVariables.size() > 0) {
			sb.append("The following Environment variables must be set: ").append(missingVariables);
			
			if (setVariables.size() > 0) {
				sb.append(" (already set variables - ").append(setVariables).append(")");
			}
		}
		
		return sb.toString();
	}
}
