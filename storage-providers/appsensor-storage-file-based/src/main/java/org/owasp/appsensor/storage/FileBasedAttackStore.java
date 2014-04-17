package org.owasp.appsensor.storage;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import org.joda.time.DateTime;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.User;
import org.owasp.appsensor.configuration.ExtendedConfiguration;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.AttackListener;
import org.owasp.appsensor.logging.Logger;
import org.owasp.appsensor.util.DateUtils;
import org.owasp.appsensor.util.FileUtils;

import com.google.gson.Gson;

/**
 * This is a reference implementation of the {@link AttackStore}.
 * 
 * Implementations of the {@link AttackListener} interface can register with 
 * this class and be notified when new {@link Attack}s are added to the data store 
 * 
 * This implementation is file-based and has the feature that it will load previous 
 * {@link Attack}s if configured to do so.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class FileBasedAttackStore extends AttackStore {
	
	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(FileBasedAttackStore.class);
	
	public static final String DEFAULT_FILE_PATH = File.separator + "tmp";
	
	public static final String DEFAULT_FILE_NAME = "attacks.txt";
	
	public static final String FILE_PATH_CONFIGURATION_KEY = "filePath";
	
	public static final String FILE_NAME_CONFIGURATION_KEY = "fileName";
	
	private Gson gson = new Gson();
	
	private Path path = null;
	
	private ExtendedConfiguration extendedConfiguration = new ExtendedConfiguration();
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		logger.warning("Security attack " + attack.getDetectionPoint().getId() + " triggered by user: " + attack.getUser().getUsername());
	       
		writeAttack(attack);
		
		super.notifyListeners(attack);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Attack> findAttacks(SearchCriteria criteria) {
		if (criteria == null) {
			throw new IllegalArgumentException("criteria must be non-null");
		}
		
		Collection<Attack> matches = new ArrayList<Attack>();
		
		User user = criteria.getUser();
		DetectionPoint detectionPoint = criteria.getDetectionPoint();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds(); 
		DateTime earliest = DateUtils.fromString(criteria.getEarliest());
		
		Collection<Attack> attacks = loadAttacks();
		
		for (Attack attack : attacks) {
			//check user match if user specified
			boolean userMatch = (user != null) ? user.equals(attack.getUser()) : true;
			
			//check detection system match if detection systems specified
			boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
					detectionSystemIds.contains(attack.getDetectionSystemId()) : true;
			
			//check detection point match if detection point specified
			boolean detectionPointMatch = (detectionPoint != null) ? 
					detectionPoint.getId().equals(attack.getDetectionPoint().getId()) : true;
			
			boolean earliestMatch = (earliest != null) ? earliest.isBefore(DateUtils.fromString(attack.getTimestamp())) : true;
					
			if (userMatch && detectionSystemMatch && detectionPointMatch && earliestMatch) {
				matches.add(attack);
			}
		}
		
		return matches;
	}

	protected void writeAttack(Attack attack) {
		String json = gson.toJson(attack);
		
		try {
			Files.write(getPath(), Arrays.asList(json), StandardCharsets.UTF_8, StandardOpenOption.APPEND, StandardOpenOption.WRITE);
		} catch (IOException e) {
			logger.error("Error occurred loading writing event file to path: " + getPath(), e);
		}
	}
	
	protected Collection<Attack> loadAttacks() {
		Collection<Attack> attacks = new ArrayList<>();
		
		try {
			Collection<String> lines = Files.readAllLines(getPath());
			
			for (String line : lines) {
				Attack attack = gson.fromJson(line, Attack.class);
				
				attacks.add(attack);
			}
		} catch (IOException e) {
			logger.error("Error occurred loading configured attack file from path: " + getPath(), e);
		}
		
		return attacks;
	}
	
	protected Path getPath() {
		if (path != null && Files.exists(path)) {
			return path;
		}
		
		path = FileUtils.getOrCreateFile(lookupFilePath(), lookupFileName());
		
		return path;
	}
	
	protected String lookupFilePath() {
		ExtendedConfiguration configuration = AppSensorServer.getInstance().getAttackStore().getExtendedConfiguration();
		
		return configuration.findValue(FILE_PATH_CONFIGURATION_KEY, DEFAULT_FILE_PATH);
	}
	
	protected String lookupFileName() {
		ExtendedConfiguration configuration = AppSensorServer.getInstance().getAttackStore().getExtendedConfiguration();
		
		return configuration.findValue(FILE_NAME_CONFIGURATION_KEY, DEFAULT_FILE_NAME);
	}
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ExtendedConfiguration getExtendedConfiguration() {
		return extendedConfiguration;
	}
	
	public void setExtendedConfiguration(ExtendedConfiguration extendedConfiguration) {
		this.extendedConfiguration = extendedConfiguration;
	}
	
}
