package org.owasp.appsensor.util;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.logging.Logger;

public class FileUtils {

	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(FileUtils.class);
	
	public static Path getOrCreateFile(String filePath, String fileName) {
		Path path = null;
		
		Path directory = Paths.get(filePath);
		
		Path file = directory.resolve(fileName);
		
		if (Files.exists(file)) {
			path = file;
		} else if (Files.notExists(file)) {
			try {
			    // Create the empty file with default permissions
			    path = Files.createFile(file);
			} catch (FileAlreadyExistsException e) {
				logger.error("File already exists (shouldn't happen): " + file, e);
			} catch (IOException e) {
			    // Some other sort of failure, such as permissions.
				logger.error("Permissions failure for file creation: " + file, e);
			}
		}

		return path;
	}
	
}
