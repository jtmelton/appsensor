package org.owasp.appsensor.block.store.resources;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import org.junit.Test;
import org.owasp.appsensor.block.store.domain.BlockRequest;
import org.owasp.appsensor.block.store.service.BlockList;
import org.owasp.appsensor.block.store.service.BlockListFactory;

public class BlockResourceTest {

	private final BlockList blockList = BlockListFactory.getInstance();
	private final BlockResource resource = new BlockResource(blockList);
	
	@Test
	public void testFindActiveScans() {

		// { }
		addInvalid( new BlockRequest() );
		
		// { "ipAddress": "1.2.3.4" }
		addInvalid( new BlockRequest("1.2.3.4", null, null) );
		
		// { "resource": "/some/url" }
		addInvalid( new BlockRequest(null, "/some/url", null) );
		
		// { "milliseconds": 2500 }
		addInvalid( new BlockRequest(null, null, 2500L) );
		
		// { "ipAddress": "a.b.c.d", "milliseconds": 2500 }
		addInvalid( new BlockRequest("a.b.c.d", null, 2500L) );

		// { "ipAddress": "1.2.3.4", "milliseconds": -50 }
		addInvalid( new BlockRequest("1.2.3.4", null, -50L) );
		
		// { "ipAddress": "1.2.3.4", "milliseconds": 1000 }
		addValid( new BlockRequest("1.2.3.4", null, 1000L), 1);
	
		// { "resource": "/some/url", "milliseconds": 2000 }
		addValid( new BlockRequest(null, "/some/url", 2000L), 2);
		
		// { "ipAddress": "5.5.5.5", "resource": "/other/url", "milliseconds": 3000 }
		addValid( new BlockRequest("5.5.5.5", "/other/url", 3000L), 3);
		
		// { "ipAddress": "1.2.3.4", "milliseconds": 4000 }
		addValid( new BlockRequest("1.2.3.4", null, 4000L), 3);

	}
	
	private void addInvalid(BlockRequest request) {
		try {
			resource.addBlock(request);
			fail("shouldn't reach this");
		} catch(WebApplicationException e) {
			assertThat( e.getResponse().getStatus() , is(400) );
		}
		
		assertThat( blockList.getAllBlocks().size() , is(0) );
	}
	
	private void addValid(BlockRequest request, int expectedSize) {
		final Response response = resource.addBlock(request);
		assertThat( response.getStatus() , is(200) );
		
		assertThat( blockList.getAllBlocks().size() , is(expectedSize) );
	}

}