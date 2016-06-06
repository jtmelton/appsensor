package org.owasp.appsensor.block.store.resources;

import java.util.Collection;

import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.owasp.appsensor.block.store.domain.Block;
import org.owasp.appsensor.block.store.domain.BlockRequest;
import org.owasp.appsensor.block.store.service.BlockList;

import com.google.common.net.InetAddresses;

@Path("/api/v1.0/blocks")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class BlockResource {

    private final BlockList blockList;

    public BlockResource(BlockList blockList) {
        this.blockList = blockList;
    }
    
    @POST
    public Response addBlock(@Valid BlockRequest block) {
    	validateBlock(block);
    	
    	blockList.add(block);
    	
    	return Response.ok("Block Request Successful.").build();
    }
    
    @GET
    public Response getBlocks() {
    	final Collection<Block> blocks = blockList.getAllBlocks();
    	
    	return Response.ok(blocks).build();
    }
    
    private void validateBlock(BlockRequest block) {

    	if(!block.appliesToIpAddress() && !block.appliesToResource()) {
    		throw new WebApplicationException("You must specify one or both of [IP address, resource]",
                    Response.Status.BAD_REQUEST);
    	}
    	
        // has to be neither or both, not one or the other
        if( block.getMilliseconds() == null || block.getMilliseconds() <= 0L ) {
            throw new WebApplicationException("You must specify a (positive) number of milliseconds to block for (from now)",
                    Response.Status.BAD_REQUEST);
        }
        
        // if IP exists, must be valid
        if( block.appliesToIpAddress() && !InetAddresses.isInetAddress(block.getIpAddress()) ) {
            throw new WebApplicationException("IP Address must be valid.",
                    Response.Status.BAD_REQUEST);
        }
    }

}