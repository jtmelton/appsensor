package org.owasp.appsensor.block.proxy.integration;

//import io.dropwizard.db.DataSourceFactory;
//import io.dropwizard.testing.ResourceHelpers;
//import io.dropwizard.testing.junit.DropwizardAppRule;
//
//import org.flywaydb.core.Flyway;
//import org.joda.time.DateTime;
//import org.junit.After;
//import org.junit.AfterClass;
//import org.junit.Before;
//import org.junit.BeforeClass;
//import org.junit.ClassRule;
//import org.junit.Test;
//import org.owasp.appsensor.blockproxy.BlockProxyApplication;
//import org.owasp.appsensor.blockproxy.BlockProxyConfiguration;
//import org.owasp.appsensor.blockproxy.auth.RequestHeaderAuthenticationFilter;
//import org.owasp.appsensor.blockproxy.domain.Block;
//
//import javax.ws.rs.WebApplicationException;
//import javax.ws.rs.client.Client;
//import javax.ws.rs.client.ClientBuilder;
//import javax.ws.rs.core.GenericType;
//
//import java.util.Collection;
//
//import static org.assertj.core.api.Assertions.assertThat;

/**
 * User: johnmelton
 * Date: 7/30/15
 */
public class BlockIntegrationTest {

//    private static final String CONFIG_PATH = ResourceHelpers.resourceFilePath("test-block-store.yml");
//
//    @ClassRule
//    public static final DropwizardAppRule<BlockProxyConfiguration> RULE = new DropwizardAppRule<BlockProxyConfiguration>(
//            BlockProxyApplication.class, CONFIG_PATH);//,
//
//    private Client client;
//    private static Flyway flyway;
//
//    @BeforeClass
//    public static void setupClass() {
//        flyway = new Flyway();
//        DataSourceFactory f = RULE.getConfiguration().getDataSourceFactory();
//        flyway.setDataSource(f.getUrl(), f.getUser(), f.getPassword());
//        //        flyway.setSchemas("sast_agent_v2");
//        flyway.clean();
//        flyway.migrate();
//    }
//
//    // when we're done, destroy the db
//    @AfterClass
//    public static void teardownClass() throws Exception {
//        flyway.clean();
//    }
//
//    @Before
//    public void setUp() throws Exception {
//        client = ClientBuilder.newClient();
//    }
//
//    @After
//    public void tearDown() throws Exception {
//        client.close();
//    }
//
//    @Test(expected = WebApplicationException.class)
//    public void testNoAuthHeader() throws Exception {
//        final Integer count = client.target("http://localhost:" + RULE.getLocalPort() + "/api/v2/scans/active")
//                .request()
//                .get(Integer.class);
//    }
//
//    @Test(expected = WebApplicationException.class)
//    public void testInvalidAuthenticationWrongHeaderName() throws Exception {
//        final Integer count = client.target("http://localhost:" + RULE.getLocalPort() + "/api/v2/scans/active")
//                .request()
//                .header("wrong_", RequestHeaderAuthenticationFilter.AUTH_HEADER_VALUE)
//                .get(Integer.class);
//    }
//
//    @Test(expected = WebApplicationException.class)
//    public void testInvalidAuthenticationWrongHeaderValue() throws Exception {
//        final Integer count = client.target("http://localhost:" + RULE.getLocalPort() + "/api/v2/scans/active")
//                .request()
//                .header(RequestHeaderAuthenticationFilter.AUTH_HEADER_NAME, "wrong_")
//                .get(Integer.class);
//    }
//
//    @Test
//    public void testScansFromLastWeek() throws Exception {
//        GenericType<Collection<Block>> responseType = new GenericType<Collection<Block>>() { };
//
//        final DateTime oneHourAhead = DateTime.now().plusDays(1);
//        final DateTime oneWeekAgo = DateTime.now().minusWeeks(1);
//
//        final Collection<Block> none = client.target("http://localhost:" + RULE.getLocalPort() + "/api/v2/scans/status")
//                .queryParam("state", "SUCCESS")
//                .queryParam("application_id", "1")
//                .queryParam("start_time", oneWeekAgo)
//                .queryParam("end_time", oneHourAhead)
//                .queryParam("show_all_per_app", false)
//                .request()
//                .header(RequestHeaderAuthenticationFilter.AUTH_HEADER_NAME, RequestHeaderAuthenticationFilter.AUTH_HEADER_VALUE)
//                .get(responseType);
//        assertThat(none.size()).isEqualTo(0);
//
//        final Collection<Block> one = client.target("http://localhost:" + RULE.getLocalPort() + "/api/v2/scans/status")
//                .queryParam("state", "IN_PROGRESS,SUCCESS")
//                .queryParam("application_id", "5")
//                .queryParam("start_time", oneWeekAgo)
//                .queryParam("end_time", oneHourAhead)
//                .queryParam("show_all_per_app", false)
//                .request()
//                .header(RequestHeaderAuthenticationFilter.AUTH_HEADER_NAME, RequestHeaderAuthenticationFilter.AUTH_HEADER_VALUE)
//                .get(responseType);
//
//        assertThat(one.size()).isEqualTo(1);
//    }
//
//    @Test
//    public void testShowAllPerApp() throws Exception {
//        GenericType<Collection<Block>> responseType = new GenericType<Collection<Block>>() { };
//
//        final Collection<Block> none = client.target("http://localhost:" + RULE.getLocalPort() + "/api/v2/scans/status")
//                .queryParam("application_id", "10,25")
//                .queryParam("show_all_per_app", false)
//                .request()
//                .header(RequestHeaderAuthenticationFilter.AUTH_HEADER_NAME, RequestHeaderAuthenticationFilter.AUTH_HEADER_VALUE)
//                .get(responseType);
//        assertThat(none.size()).isEqualTo(2);
//
//        final Collection<Block> one = client.target("http://localhost:" + RULE.getLocalPort() + "/api/v2/scans/status")
//                .queryParam("application_id", "10,25")
//                .queryParam("show_all_per_app", true)
//                .request()
//                .header(RequestHeaderAuthenticationFilter.AUTH_HEADER_NAME, RequestHeaderAuthenticationFilter.AUTH_HEADER_VALUE)
//                .get(responseType);
//
//        assertThat(one.size()).isEqualTo(5);
//    }
//
//    @Test
//    public void testActiveScans() throws Exception {
//
//        final Integer count = client.target("http://localhost:" + RULE.getLocalPort() + "/api/v2/scans/active")
//                .request()
//                .header(RequestHeaderAuthenticationFilter.AUTH_HEADER_NAME, RequestHeaderAuthenticationFilter.AUTH_HEADER_VALUE)
//                .get(Integer.class);
//        assertThat(count).isEqualTo(3);
//    }

}
