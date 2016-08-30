package org.owasp.appsensor.storage.elasticsearch;

import org.junit.runner.RunWith;
import org.owasp.appsensor.local.analysis.ReferenceStatisticalEventAnalysisEngineTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;


/**
 * Test basic elasticsearch based * Store's by extending the ReferenceStatisticalEventAnalysisEngineTest
 * and only doing the file based setup. All of the same tests execute, but with the elastic search
 * based store.
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = ElasticTestConfiguration.class, loader = AnnotationConfigContextLoader.class)
public class ElasticSearchEventStorageTest extends ReferenceStatisticalEventAnalysisEngineTest {


}
