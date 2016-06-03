package org.owasp.appsensor.storage.riak;

import com.basho.riak.client.api.RiakClient;
import com.basho.riak.client.api.commands.datatypes.FetchSet;
import com.basho.riak.client.api.commands.datatypes.SetUpdate;
import com.basho.riak.client.api.commands.datatypes.UpdateSet;
import com.basho.riak.client.core.query.Location;
import com.basho.riak.client.core.query.Namespace;
import com.basho.riak.client.core.query.crdt.types.RiakSet;
import com.basho.riak.client.core.util.BinaryValue;
import com.google.gson.Gson;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.ResponseListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.ResponseStore;
import org.slf4j.Logger;
import org.springframework.core.env.Environment;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.inject.Inject;
import javax.inject.Named;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;

import java.util.concurrent.ExecutionException;

/**
 * This is a reference implementation of the {@link ResponseStore}.
 * 
 * Implementations of the {@link ResponseListener} interface can register with 
 * this class and be notified when new {@link Response}s are added to the data store 
 * 
 * The implementation is trivial and simply stores the {@link Response} in an in-memory collection.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Named
@Loggable
public class RiakResponseStore extends ResponseStore {

	public static final String RIAK_SERVER_ADDRESS = "RIAK_SERVER_ADDRESS";

	private Logger logger;

	@Inject
	private Environment environment;

	private Location responses;

	private RiakClient client;
	private Gson gson;


	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addResponse(Response response) {
		logger.warn("Security response " + response.getAction() + " triggered for user: " + response.getUser().getUsername());

		String json = gson.toJson(response);

		try {
			client.execute(
					new UpdateSet.Builder(
							responses, new SetUpdate().add(json)
					).build()
			);
		} catch (ExecutionException e) {
			if (logger != null) {
				logger.error("Adding response to RiakDB failed", e);
			}
			e.printStackTrace();
		} catch (InterruptedException e) {
			if (logger != null) {
				logger.error("Adding response to RiakDB was interrupted", e);
			}
			e.printStackTrace();
		}

		super.notifyListeners(response);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> findResponses(SearchCriteria criteria) {
		return findResponses(criteria, loadResponses());
	}

	private Collection<Response> loadResponses() {
		Collection<Response> responsesCollection = new ArrayList<Response>();
		try {
			RiakSet set = client.execute(
					new FetchSet.Builder(responses)
							.build()
			).getDatatype();

			for(BinaryValue binaryValue: set.view()) {
				Response response = gson.fromJson(binaryValue.toStringUtf8(), Response.class);
				responsesCollection.add(response);
				}
		} catch (ExecutionException e) {
			logger.error("Fetching responses from RiakDB failed", e);
			e.printStackTrace();
		} catch (InterruptedException e) {
			logger.error("Fetching responses from RiakDB was interrupted", e);
			e.printStackTrace();
		}

		return responsesCollection;
	}

	@PostConstruct
	private void initializeRiak() {
		client = initializeConnection();

		if (client == null) {
			client = defaultInitialize();
		}

		responses = new Location(new Namespace("sets", "appsensor"), "responses");
	}

	@PreDestroy
	private void destroyClient() {
		client.shutdown();
	}

	private RiakClient defaultInitialize() {
		RiakClient client = null;
		try {
			String addresses = environment.getProperty(RIAK_SERVER_ADDRESS);
			client = RiakClient.newClient(addresses.split(","));
		} catch (UnknownHostException e) {
			if (logger != null) {
				logger.error("Riak connection could not be made", e);
			}
			e.printStackTrace();
		}
		return client;
	}

	/**
	 * Default implementation - override if you want a custom initializer.
	 *
	 * @return StatefulRedisConnection you want to write to.
	 */
	public RiakClient initializeConnection() {
		return null;
	}
}
