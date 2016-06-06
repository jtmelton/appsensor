package org.owasp.appsensor.block.proxy.jobs;

import org.owasp.appsensor.block.proxy.domain.BlockCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.spinscale.dropwizard.jobs.Job;
import de.spinscale.dropwizard.jobs.annotations.Every;

@Every("10s")
public class CleanupBlockCacheJob extends Job {

	private final static Logger LOGGER = LoggerFactory.getLogger(CleanupBlockCacheJob.class);
	
	private final BlockCache blockCache = BlockCache.get();
	
    @Override
    public void doJob() {
		LOGGER.info("Executing block cache purge.");
		
        blockCache.removeExpired();
    }

}