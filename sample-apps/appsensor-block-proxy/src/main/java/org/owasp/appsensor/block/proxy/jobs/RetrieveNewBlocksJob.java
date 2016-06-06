package org.owasp.appsensor.block.proxy.jobs;

import java.util.Collection;

import javax.ws.rs.client.Client;
import javax.ws.rs.core.GenericType;

import org.owasp.appsensor.block.proxy.BlockProxyConfiguration;
import org.owasp.appsensor.block.proxy.domain.Block;
import org.owasp.appsensor.block.proxy.domain.BlockCache;
import org.owasp.appsensor.block.proxy.domain.JerseyClientCache;
import org.owasp.appsensor.block.proxy.util.ConfigurationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.spinscale.dropwizard.jobs.Job;
import de.spinscale.dropwizard.jobs.annotations.Every;

@Every("10s")
public class RetrieveNewBlocksJob extends Job {

	private final static Logger LOGGER = LoggerFactory.getLogger(RetrieveNewBlocksJob.class);
	
	private final BlockCache blockCache = BlockCache.get();
	
	private Client client = JerseyClientCache.getInstance();
	
	private BlockProxyConfiguration configuration = ConfigurationContext.get();
	
    @Override
    public void doJob() {
		ensureInitialized();
		
		if(client == null) {
			LOGGER.info("Cannot perform load as Jersey client cannot be configured.");
		}
		
		Collection<Block> blocks = retrieveBlocks();
		
		blockCache.addAll(blocks);
    }
	
	private void ensureInitialized() {
		if(client == null) {
			client = JerseyClientCache.getInstance();
		}
	}

	private Collection<Block> retrieveBlocks() {
		GenericType<Collection<Block>> blockType = new GenericType<Collection<Block>>() {};
		
		Collection<Block> blocks = client.target(configuration.getBlockStoreUrl()).request().get(blockType);
		
		LOGGER.info("Adding {} retrieved blocks.", blocks.size());
		
		return blocks;
	}
}