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
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.AttackListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.AttackStore;
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
 * This is a reference implementation of the {@link AttackStore}.
 * <p>
 * Implementations of the {@link AttackListener} interface can register with
 * this class and be notified when new {@link Attack}s are added to the data store
 * <p>
 * The implementation is trivial and simply stores the {@link Attack} in an in-memory collection.
 *
 * @author Robert Przystasz  (robert.przystasz@gmail.com)
 * @author Bartosz Wyględacz (bartosz.wygledacz@gmail.com)
 * @author Michal Warzecha   (mwarzechaa@gmail.com)
 * @author Magdalena Idzik   (maddie@pwnag3.net)
 */
@Named
@Loggable
public class RiakAttackStore extends AttackStore {

    public static final String RIAK_SERVER_ADDRESS = "RIAK_SERVER_ADDRESS";

    private Logger logger;

    @Inject
    private Environment environment;

    private Location attacks;

    private RiakClient client;
    private Gson gson;


    /**
     * {@inheritDoc}
     */
    @Override
    public void addAttack(Attack attack) {
        logger.warn("Security attack " + attack.getDetectionPoint().getLabel() + " triggered by user: " + attack.getUser().getUsername());

        String json = gson.toJson(attack);

        try {
            client.execute(
                    new UpdateSet.Builder(
                            attacks, new SetUpdate().add(json)
                    ).build()
            );
        } catch (ExecutionException e) {
            if (logger != null) {
                logger.error("Adding attack to RiakDB failed", e);
            }
            e.printStackTrace();
        } catch (InterruptedException e) {
            if (logger != null) {
                logger.error("Adding attack to RiakDB was interrupted", e);
            }
            e.printStackTrace();
        }

        super.notifyListeners(attack);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<Attack> findAttacks(final SearchCriteria criteria) {
        if (criteria == null) {
            throw new IllegalArgumentException("criteria must be non-null");
        }

        Collection<Attack> matches = new ArrayList<Attack>();

        try {
            RiakSet set = client.execute(
                    new FetchSet.Builder(attacks)
                            .build()
            ).getDatatype();
            for(BinaryValue binaryValue: set.view()) {
                Attack attack = gson.fromJson(binaryValue.toStringUtf8(), Attack.class);
                if (isMatchingAttack(criteria, attack)) {
                    matches.add(attack);
                }
            }
        } catch (ExecutionException e) {
            logger.error("Fetching attacks from RiakDB failed", e);
            e.printStackTrace();
        } catch (InterruptedException e) {
            logger.error("Fetching attacks from RiakDB was interrupted", e);
            e.printStackTrace();
        }

        return matches;
    }

    @PostConstruct
    private void initializeRiak() {
        client = initializeConnection();

        if (client == null) {
            client = defaultInitialize();
        }

        attacks = new Location(new Namespace("sets", "appsensor"), "attacks");
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
