package org.owasp.appsensor.demo;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.appsensor.DemoAppsensorLocalApplication;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = DemoAppsensorLocalApplication.class)
@WebAppConfiguration
public class DemoAppsensorLocalApplicationTests {

	@Test
	public void contextLoads() {
	}

}
