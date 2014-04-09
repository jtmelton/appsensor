package org.owasp.appsensor;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:base-context.xml"})
public class AppSensorServerTest {

	@Autowired
	private AppSensorServer appSensorServer;
	
	@Test
	public void testInstanciation() {
		assertNotNull("Server instance is null", appSensorServer);
	}
}
