package org.owasp.appsensor.storage.mongo;

import com.mongodb.BasicDBObject;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoDatabase;
import de.flapdoodle.embed.mongo.MongodExecutable;
import de.flapdoodle.embed.mongo.MongodProcess;
import de.flapdoodle.embed.mongo.MongodStarter;
import de.flapdoodle.embed.mongo.config.IMongodConfig;
import de.flapdoodle.embed.mongo.config.MongodConfigBuilder;
import de.flapdoodle.embed.mongo.config.Net;
import de.flapdoodle.embed.mongo.distribution.Version;
import de.flapdoodle.embed.process.runtime.Network;
import org.junit.After;
import org.junit.Before;
import org.owasp.appsensor.local.analysis.ReferenceStatisticalEventAnalysisEngineTest;

/**
 * Test basic Mongo based * Store's by extending the ReferenceStatisticalEventAnalysisEngineTest
 * and only doing the file based setup. All of the same tests execute, but with the Mongo
 * based stores instead of the memory based stores.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class MongodbEventStorageTest extends ReferenceStatisticalEventAnalysisEngineTest {

	private static MongodStarter starter;

	private MongodExecutable mongodExecutable;
	private MongodProcess mongodProcess;
	
	private int port = 27017;	//default
	
	@Before
	public void initialize() throws Exception {
		starter = MongodStarter.getDefaultInstance();
		startMongoProcess();
		cleanupMongoCollections();
	}
	
	private void cleanupMongoCollections() {
		
		try {
			MongoClient mongoClient = new MongoClient("localhost", port);
			MongoDatabase db = mongoClient.getDatabase("appsensor_db");
			db.getCollection("events").deleteMany(new BasicDBObject());
			db.getCollection("attacks").deleteMany(new BasicDBObject());
			db.getCollection("responses").deleteMany(new BasicDBObject());
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	public void startMongoProcess() throws Exception {

	    IMongodConfig mongodConfig = new MongodConfigBuilder()
	        .version(Version.Main.V3_2)
	        .net(new Net(port, Network.localhostIsIPv6()))
	        .build();

        mongodExecutable = starter.prepare(mongodConfig);
       	mongodProcess = mongodExecutable.start();
	}

	@After
	public void teardown() throws Exception {
		if (mongodProcess != null) {
			mongodProcess.stop();
		}

		if (mongodExecutable != null) {
            mongodExecutable.stop();
        }
	}

}
