package org.owasp.appsensor.storage.mongo;

import java.net.UnknownHostException;

import org.junit.After;
import org.junit.Before;
import org.owasp.appsensor.local.analysis.ReferenceStatisticalEventAnalysisEngineTest;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.Mongo;

import de.flapdoodle.embed.mongo.MongodExecutable;
import de.flapdoodle.embed.mongo.MongodStarter;
import de.flapdoodle.embed.mongo.config.IMongodConfig;
import de.flapdoodle.embed.mongo.config.MongodConfigBuilder;
import de.flapdoodle.embed.mongo.config.Net;
import de.flapdoodle.embed.mongo.distribution.Version;
import de.flapdoodle.embed.process.runtime.Network;


/**
 * Test basic Mongo based * Store's by extending the ReferenceStatisticalEventAnalysisEngineTest
 * and only doing the file based setup. All of the same tests execute, but with the Mongo
 * based stores instead of the memory based stores.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class MongodbEventStorageTest extends ReferenceStatisticalEventAnalysisEngineTest {

	private MongodExecutable mongodExecutable;
	
	private int port = 27017;	//default
	
	@Before
	public void initialize() throws Exception {
		startMongoProcess();
		cleanupMongoCollections();
	}
	
	private void cleanupMongoCollections() {
		try {
			Mongo mongoClient = new Mongo("localhost",port);
			DB db = mongoClient.getDB("appsensor_db");
			db.getCollection("events").remove(new BasicDBObject());
			db.getCollection("attacks").remove(new BasicDBObject());
			db.getCollection("responses").remove(new BasicDBObject());
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
	}
	
	public void startMongoProcess() throws Exception {
		MongodStarter starter = MongodStarter.getDefaultInstance();

	    IMongodConfig mongodConfig = new MongodConfigBuilder()
	        .version(Version.Main.PRODUCTION)
	        .net(new Net(port, Network.localhostIsIPv6()))
	        .build();

        mongodExecutable = starter.prepare(mongodConfig);
       	mongodExecutable.start();
	}

	@After
	public void teardown() throws Exception {
		if (mongodExecutable != null) {
            mongodExecutable.stop();
        }
	}
	
}
