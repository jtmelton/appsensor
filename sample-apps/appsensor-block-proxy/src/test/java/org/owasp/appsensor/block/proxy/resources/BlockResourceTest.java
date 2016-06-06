package org.owasp.appsensor.block.proxy.resources;

//import com.google.common.base.Optional;
//import com.google.common.net.InetAddresses;
//
//import io.dropwizard.jersey.params.BooleanParam;
//import io.dropwizard.jersey.params.DateTimeParam;
//
//import org.joda.time.DateTime;
//import org.joda.time.DateTimeZone;
//import org.junit.Test;
//import org.owasp.appsensor.block.proxy.resources.BlockResource;
//import org.owasp.appsensor.block.store.domain.BlockRequest;
//import org.owasp.appsensor.block.store.service.BlockList;
//import org.owasp.appsensor.blockproxy.domain.Block;
//import org.owasp.appsensor.blockproxy.jdbi.ScanDao;
//
//import javax.validation.Valid;
//import javax.ws.rs.GET;
//import javax.ws.rs.POST;
//import javax.ws.rs.WebApplicationException;
//import javax.ws.rs.core.Response;
//
//import java.sql.Timestamp;
//import java.util.Arrays;
//import java.util.Collection;
//import java.util.List;
//
//import static org.hamcrest.CoreMatchers.is;
//import static org.hamcrest.MatcherAssert.assertThat;
//import static org.mockito.Mockito.mock;
//import static org.mockito.Mockito.when;

/**
 * User: johnmelton
 * Date: 7/24/15
 */
public class BlockResourceTest {
	
	
	
	
	
//    private final ScanDao dao = mock(ScanDao.class);
//    private final BlockResource resource = new BlockResource(dao);
//    private final DateTime now = DateTime.now();
//    private final Timestamp timestamp = new Timestamp(now.getMillis());
//
//    @Test
//    public void testFindActiveScans() {
//        final Collection<Block> noScans = mock(Collection.class);
//        final List oneScan = Arrays.asList(new Block());
//
//        when(dao.findScans(Arrays.asList("SUCCESS"), Arrays.asList(1L), timestamp, timestamp)).thenReturn(noScans);
//        when(dao.findScans(Arrays.asList("IN_PROGRESS"), Arrays.asList(1L), timestamp, timestamp)).thenReturn(oneScan);
//
//        final Response noResults = resource.findScans(
//                Optional.of("SUCCESS"),
//                Optional.of("1"),
//                Optional.of(new DateTimeParam(now.toDateTime(DateTimeZone.UTC).toString())),
//                Optional.of(new DateTimeParam(now.toDateTime(DateTimeZone.UTC).toString())),
//                Optional.of(new BooleanParam("false")));
//
//        final Response oneResult = resource.findScans(
//                Optional.of("IN_PROGRESS"),
//                Optional.of("1"),
//                Optional.of(new DateTimeParam(now.toDateTime(DateTimeZone.UTC).toString())),
//                Optional.of(new DateTimeParam(now.toDateTime(DateTimeZone.UTC).toString())),
//                Optional.of(new BooleanParam("false")));
//
//        assertThat(((Collection<Block>)noResults.getEntity()).size(),
//                is(noScans.size()));
//
//        assertThat(((Collection<Block>)oneResult.getEntity()).size(),
//                is(oneScan.size()));
//    }
//
//    @Test(expected = WebApplicationException.class)
//    public void testFindActiveScansInvalidState() {
//        final Collection<Block> scans = mock(Collection.class);
//
//        Timestamp timestamp = new Timestamp(now.getMillis());
//        when(dao.findScans(Arrays.asList("IN_PROGRESS"), Arrays.asList(1L), timestamp, timestamp)).thenReturn(scans);
//
//        final Response results = resource.findScans(
//                Optional.of("SOME_INVALID_STATE"),
//                Optional.of("1"),
//                Optional.of(new DateTimeParam(now.toString())),
//                Optional.of(new DateTimeParam(now.toString())),
//                Optional.of(new BooleanParam("false")));
//
//        assertThat(((Collection<Block>)results.getEntity()).size(),
//                is(scans.size()));
//    }

}