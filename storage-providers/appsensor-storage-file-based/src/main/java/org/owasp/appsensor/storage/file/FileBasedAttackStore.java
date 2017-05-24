package org.owasp.appsensor.storage.file;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import javax.inject.Named;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.AttackListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.AttackStore;
import org.owasp.appsensor.core.util.FileUtils;
import org.slf4j.Logger;

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
 * @author Raphaël Taban
 */
@Named
@Loggable
public class FileBasedAttackStore extends AttackStore {

	private Logger logger;

	private String filePath;

	private String fileName;

	public static final String DEFAULT_FILE_PATH = System.getProperty("java.io.tmpdir");

	public static final String DEFAULT_FILE_NAME = "attacks.txt";

	public static final String FILE_PATH_CONFIGURATION_KEY = "filePath";

	public static final String FILE_NAME_CONFIGURATION_KEY = "fileName";

	private Gson gson = new Gson();

	private Path path = null;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		logger.warn("Security attack " + attack.getName() + " triggered by user: " + attack.getUser().getUsername());

		writeAttack(attack);

		super.notifyListeners(attack);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Attack> findAttacks(SearchCriteria criteria) {
		return findAttacks(criteria, loadAttacks());
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
			Collection<String> lines = Files.readAllLines(getPath(), StandardCharsets.UTF_8);

			for (String line : lines) {
				Attack attack = gson.fromJson(line, Attack.class);

				attacks.add(attack);
			}
		} catch (IOException e) {
			logger.error("Error occurred loading configured attack file from path: " + getPath(), e);
		}

		return attacks;
	}

	public Path getPath() {
		if (path != null && Files.exists(path)) {
			return path;
		}

		path = FileUtils.getOrCreateFile(lookupFilePath(), lookupFileName());

		logger.info("AppSensor attack file store is located at: " + path.toAbsolutePath().toString());

		return path;
	}

	protected String lookupFilePath() {
		return (filePath != null) ? filePath : DEFAULT_FILE_PATH;
	}

	protected String lookupFileName() {
		return (fileName != null) ? fileName : DEFAULT_FILE_NAME;
	}

	public void setFilePath(String filePath) {
		this.filePath = filePath;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

}