package org.owasp.appsensor.block.proxy.domain;

import java.util.Collection;
import java.util.concurrent.ConcurrentSkipListSet;

import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;

public class BlockCache {
	
	private final static Logger LOGGER = LoggerFactory.getLogger(BlockCache.class);
	
	private ConcurrentSkipListSet<Block> cache = new ConcurrentSkipListSet<>();
	
	private static final BlockCache INSTANCE = new BlockCache();
	
	private BlockCache() {}
	
	public static BlockCache get() {
		return INSTANCE;
	}
	
	public void add(Block block) {
		cache.add(block);
	}
	
	public void addAll(Collection<Block> blocks) {
		cache.addAll(blocks);
	}
	
	public void removeExpired() {
		final Collection<Block> expired = Lists.newArrayList(); 
		
		DateTime now = DateTime.now();
		
		for(Block block : cache) {
			if(!block.isActive(now)) {
				expired.add(block);
			}
		}
		
		if(! expired.isEmpty()) {
			cache.removeAll(expired);
			
			LOGGER.info("Removed {} expired blocks", expired.size());
    	}
	}
	
	public boolean isBlocked(String ipAddress, String resource) {
		boolean blocked = false;
		
		DateTime now = DateTime.now();
		
		for(Block block : cache) {
			if(block.applies(ipAddress, resource, now)) {
				blocked = true;
				break;
			}
		}
		
		return blocked;
	}
	
}
