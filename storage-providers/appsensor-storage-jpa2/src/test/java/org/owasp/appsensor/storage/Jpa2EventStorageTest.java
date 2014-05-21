package org.owasp.appsensor.storage;

import org.junit.runner.RunWith;
import org.owasp.appsensor.analysis.ReferenceStatisticalEventAnalysisEngineTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;


/**
 * Test basic JPA2 based * Store's by extending the ReferenceStatisticalEventAnalysisEngineTest
 * and only doing the file based setup. All of the same tests execute, but with the jpa2
 * based stores instead of the memory based stores.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:base-context.xml"})
public class Jpa2EventStorageTest extends ReferenceStatisticalEventAnalysisEngineTest {

	
}
