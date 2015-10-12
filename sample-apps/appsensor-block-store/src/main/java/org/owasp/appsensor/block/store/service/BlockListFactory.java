package org.owasp.appsensor.block.store.service;

public final class BlockListFactory {
	
	private static final BlockList blockList = new InMemoryBlockList();

	// right now we use only the in-memory option, but this could be refactored
	// to look at configuration or env vars and use one of N implementations
	public static BlockList getInstance() {
		return blockList;
	}

}
