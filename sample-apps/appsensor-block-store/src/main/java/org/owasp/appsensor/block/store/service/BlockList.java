package org.owasp.appsensor.block.store.service;

import java.util.Collection;

import org.joda.time.DateTime;
import org.owasp.appsensor.block.store.domain.Block;
import org.owasp.appsensor.block.store.domain.BlockRequest;

public interface BlockList {

	public void add(BlockRequest block);
	
	public void remove(Block block);
	
	public boolean isBlocked(String ipAddress, String resource, DateTime time);
	
	public Collection<Block> getAllBlocks();
	
}
