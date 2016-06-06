package org.owasp.appsensor.block.store.jobs;

import java.util.Collection;

import org.joda.time.DateTime;
import org.owasp.appsensor.block.store.domain.Block;
import org.owasp.appsensor.block.store.service.BlockList;
import org.owasp.appsensor.block.store.service.BlockListFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;

import de.spinscale.dropwizard.jobs.Job;
import de.spinscale.dropwizard.jobs.annotations.Every;

@Every("30s")
public class CleanupBlockListJob extends Job {

	private final static Logger LOGGER = LoggerFactory.getLogger(CleanupBlockListJob.class);
	
	private final BlockList blockList = BlockListFactory.getInstance();
	
    @Override
    public void doJob() {
    	
    	final DateTime now = DateTime.now();
    	
    	final Collection<Block> all = blockList.getAllBlocks();
    	
    	final Collection<Block> expired = Lists.newArrayList(); 
    	
    	for(Block block : all) {
    		if(!block.isActive(now)) {
    			expired.add(block);
    		}
    	}

    	if(! expired.isEmpty()) {
    		for(Block block : expired) {
    			blockList.remove(block);
    		}
			
			LOGGER.info("Removed {} expired blocks {}", expired.size(), expired);
    	}
        
    }

}