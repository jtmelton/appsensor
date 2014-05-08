package org.owasp.appsensor.storage;

import java.nio.file.Files;

import org.junit.Before;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.analysis.ReferenceStatisticalEventAnalysisEngineTest;
import org.springframework.beans.factory.annotation.Autowired;


/**
 * Test basic FileBased * Store's by extending the ReferenceStatisticalEventAnalysisEngineTest
 * and only doing the file based setup. All of the same tests execute, but with the file
 * based stores instead of the memory based stores.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class FileBasedEventStorageTest extends ReferenceStatisticalEventAnalysisEngineTest {

	@Autowired
	private AppSensorServer appSensorServer;
	
	@Before
	public void deleteTestFiles() throws Exception {
		FileBasedEventStore eventStore = (FileBasedEventStore)appSensorServer.getEventStore();
		FileBasedAttackStore attackStore = (FileBasedAttackStore)appSensorServer.getAttackStore();
		FileBasedResponseStore responseStore = (FileBasedResponseStore)appSensorServer.getResponseStore();

		Files.deleteIfExists(eventStore.getPath());
		Files.deleteIfExists(attackStore.getPath());
		Files.deleteIfExists(responseStore.getPath());
	}
	
}
