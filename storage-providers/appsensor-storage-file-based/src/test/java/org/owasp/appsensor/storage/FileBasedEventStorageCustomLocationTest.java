package org.owasp.appsensor.storage;

import javax.inject.Inject;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.appsensor.AppSensorServer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;


/**
 * Test overriding custom locations
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:base-context-custom-files.xml"})
public class FileBasedEventStorageCustomLocationTest {

	@Inject
	private AppSensorServer appSensorServer;
	
	@Test
	public void deleteTestFiles() throws Exception {
		FileBasedEventStore eventStore = (FileBasedEventStore)appSensorServer.getEventStore();
		FileBasedAttackStore attackStore = (FileBasedAttackStore)appSensorServer.getAttackStore();
		FileBasedResponseStore responseStore = (FileBasedResponseStore)appSensorServer.getResponseStore();

		Assert.assertEquals("/tmp/as_events.txt", eventStore.getPath().toString());
		Assert.assertEquals("/tmp/as_attacks.txt", attackStore.getPath().toString());
		Assert.assertEquals("/tmp/as_responses.txt", responseStore.getPath().toString());
	}
	
}
