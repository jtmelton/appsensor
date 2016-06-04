package org.owasp.appsensor.storage.riak;

import com.basho.riak.client.api.RiakClient;
import com.basho.riak.client.api.commands.kv.DeleteValue;
import com.basho.riak.client.core.query.Location;
import com.basho.riak.client.core.query.Namespace;
import org.junit.After;
import org.junit.Before;
import org.owasp.appsensor.local.analysis.ReferenceStatisticalEventAnalysisEngineTest;
import org.springframework.core.env.Environment;

import javax.inject.Inject;
import java.util.concurrent.ExecutionException;


/**
 * Test basic Riak based * Store's by extending the ReferenceStatisticalEventAnalysisEngineTest
 * and only doing the file based setup. All of the same tests execute, but with the Riak
 * based stores instead of the memory based stores.
 *
 * @author Robert Przystasz  (robert.przystasz@gmail.com)
 * @author Bartosz Wyględacz (bartosz.wygledacz@gmail.com)
 * @author Michal Warzecha   (mwarzechaa@gmail.com)
 * @author Magdalena Idzik   (maddie@pwnag3.net)
 * @since 2.2.1
 */
public class RiakEventStorageTest extends ReferenceStatisticalEventAnalysisEngineTest implements RiakConstants {

    private RiakClient client;

    @Before
    public void initialize() throws Exception {
        startRiakProcess();
        if (client != null) {
            cleanupRiakCollections();
        }
    }

    @Inject
    private Environment environment;

    private void cleanupRiakCollections() throws ExecutionException, InterruptedException {
        cleanupSet("attacks");
        cleanupSet("events");
        cleanupSet("responses");
    }

    private void cleanupSet(String set) throws ExecutionException, InterruptedException {
        Location location = new Location(new Namespace("sets", "appsensor"), set);
        client.execute(new DeleteValue.Builder(location).build());
    }

    public void startRiakProcess() {
        try {
            String addresses = environment.getProperty(RIAK_SERVER_ADDRESS);
            int port = Integer.parseInt(environment.getProperty(RIAK_SERVER_PORT));
            client = RiakClient.newClient(port, addresses.split(","));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void testAttackCreation() throws Exception {
        if (client != null) {
            super.testAttackCreation();
        }
    }

    @After
    public void teardown() throws Exception {
        if (client != null) {
            client.shutdown();
        }
    }

}