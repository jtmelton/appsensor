package org.owasp.appsensor.block.store.service;

import java.util.Collection;
import java.util.Map;

import org.joda.time.DateTime;
import org.owasp.appsensor.block.store.domain.Block;
import org.owasp.appsensor.block.store.domain.BlockRequest;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Table;
import com.google.common.collect.Table.Cell;

public class InMemoryBlockList implements BlockList {

	private Map<String, DateTime> ipsOnly = Maps.newHashMap();
	
	private Map<String, DateTime> resourcesOnly = Maps.newHashMap();

	Table<String, String, DateTime> ipsAndResources = HashBasedTable.create();
	
	@Override
	public void add(BlockRequest block) {
		
		final DateTime blockEndTime = DateTime.now().plusMillis(block.getMilliseconds().intValue());
		
		if(block.appliesToIpAddress() && block.appliesToResource()) {
			ipsAndResources.put(block.getIpAddress(), block.getResource(), blockEndTime);
		} else if(block.appliesToIpAddress()) {
			DateTime existing = ipsOnly.get(block.getIpAddress());
			
			if(existing == null || blockEndTime.isAfter(existing)) {
				ipsOnly.put(block.getIpAddress(), blockEndTime);
			}
		} else if(block.appliesToResource()) {
			DateTime existing = resourcesOnly.get(block.getResource());
			
			if(existing == null || blockEndTime.isAfter(existing)) {
				resourcesOnly.put(block.getResource(), blockEndTime);
			}
		}
	}

	@Override
	public void remove(Block block) {

		if(block.appliesToIpAddress() && block.appliesToResource()) {
			ipsAndResources.remove(block.getIpAddress(), block.getResource());
		} else if(block.appliesToIpAddress()) {
			ipsOnly.remove(block.getIpAddress());
		} else if(block.appliesToResource()) {
			resourcesOnly.remove(block.getResource());
		}
	}

	@Override
	public boolean isBlocked(String ipAddress, String resource, DateTime time) {
		
		boolean blocked = false;
		
		DateTime ipsOnlyTime = ipsOnly.get(ipAddress);
		if(ipsOnlyTime != null && ipsOnlyTime.isAfter(time)) {
			blocked = true;
		}
		
		if(!blocked) {
			DateTime resourcesOnlyTime = resourcesOnly.get(resource);
			if(resourcesOnlyTime != null && resourcesOnlyTime.isAfter(time)) {
				blocked = true;
			}
		}
		
		if(!blocked) {
			DateTime ipsAndResourcesTime = ipsAndResources.get(ipAddress, resource);
			if(ipsAndResourcesTime != null && ipsAndResourcesTime.isAfter(time)) {
				blocked = true;
			}
		}
		
		return blocked;
	}

	@Override
	public Collection<Block> getAllBlocks() {
		
		Collection<Block> blocks = Lists.newArrayList();

		for(String ip : ipsOnly.keySet()) {
			blocks.add( new Block(ip, null, ipsOnly.get(ip)) );
		}
		
		for(String resource : resourcesOnly.keySet()) {
			blocks.add( new Block(null, resource, resourcesOnly.get(resource)) );
		}
		
		for ( Cell<String, String, DateTime> cell: ipsAndResources.cellSet() ) {
			blocks.add( new Block(cell.getRowKey(), cell.getColumnKey(), cell.getValue()) );
		}
		
		return blocks;
	}
	
}
