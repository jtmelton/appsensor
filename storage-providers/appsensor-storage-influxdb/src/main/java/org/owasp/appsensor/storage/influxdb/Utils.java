package org.owasp.appsensor.storage.influxdb;

import com.google.common.base.Preconditions;

import org.apache.commons.lang3.StringUtils;
import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.dto.QueryResult;
import org.joda.time.DateTime;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.util.DateUtils;
import org.springframework.core.env.Environment;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.annotation.PostConstruct;

/**
 * Created by john.melton on 3/11/16.
 */
public class Utils {

  // database
  public static final String DATABASE = "appsensor";

  // measurements
  public static final String EVENTS = "events";
  public static final String ATTACKS = "attacks";
  public static final String RESPONSES = "responses";

  // fields / tags
  public static final String LABEL = "label";
  public static final String USERNAME = "username";
  public static final String TIMESTAMP = "timestamp";
  public static final String DETECTION_SYSTEM = "detectionSystem";
  public static final String CATEGORY = "category";
  public static final String THRESHOLD_COUNT = "thresholdCount";
  public static final String THRESHOLD_INTERVAL_DURATION = "thresholdIntervalDuration";
  public static final String THRESHOLD_INTERVAL_UNIT = "thresholdIntervalUnit";
  public static final String RESPONSE_ACTION = "responseAction";
  public static final String RESPONSE_INTERVAL_DURATION = "responseIntervalDuration";
  public static final String RESPONSE_INTERVAL_UNIT = "responseIntervalUnit";
  public static final String JSON_CONTENT = "jsonContent";

  // env vars / sys props
  public static final String INFLUXDB_CONNECTION_STRING = "APPSENSOR_INFLUXDB_CONNECTION_STRING";
  public static final String INFLUXDB_USERNAME = "APPSENSOR_INFLUXDB_USERNAME";
  public static final String INFLUXDB_PASSWORD = "APPSENSOR_INFLUXDB_PASSWORD";

  // query mode, whether or not to look for detection point related search criteria
  public enum QueryMode {IGNORE_DETECTION_POINT, CONSIDER_DETECTION_POINT}

  public synchronized static void createDatabaseIfNotExists(InfluxDB influxDB) {
    Preconditions.checkNotNull(influxDB, "InfluxDB reference must not be null");

    Collection<String> databases = influxDB.describeDatabases();

    if(! databases.contains(DATABASE)) {
      influxDB.createDatabase(DATABASE);
    }
  }

  public static String getValue(String name, QueryResult.Series series, List<Object> record) {
    if(series == null || series.getValues() == null || series.getValues().get(0) == null) {
      return null;
    }

    if(series.getColumns().contains(name)) {
      return record.get(series.getColumns().indexOf(name)).toString();
    }

    return null;
  }

  public static String constructInfluxQL(String measurement,
                                         User user,
                                         DetectionPoint detectionPoint,
                                         Collection<String> detectionSystemIds,
                                         DateTime earliest,
                                         QueryMode queryMode) {
    String sql = "SELECT " + Utils.JSON_CONTENT + " FROM " + measurement;

    List<String> clauses = new ArrayList<>();

    if (user != null) {
      clauses.add(Utils.USERNAME + " = '" + user.getUsername() + "'");
    }

    if (detectionSystemIds != null && detectionSystemIds.size() > 0) {
      clauses.add(Utils.DETECTION_SYSTEM + " = '" + detectionSystemIds.iterator().next() + "'");
    }

    if(QueryMode.CONSIDER_DETECTION_POINT == queryMode) {
      if (detectionPoint != null) {
        if (detectionPoint.getCategory() != null) {
          clauses.add(Utils.CATEGORY + " = '" + detectionPoint.getCategory() + "'");
        }

        if (detectionPoint.getLabel() != null) {
          clauses.add(Utils.LABEL + " = '" + detectionPoint.getLabel() + "'");
        }

        if (detectionPoint.getThreshold() != null) {
          clauses.add(Utils.THRESHOLD_COUNT + " = '" + detectionPoint.getThreshold().getCount() + "'");

          if (detectionPoint.getThreshold().getInterval() != null) {
            clauses.add(
                Utils.THRESHOLD_INTERVAL_DURATION + " = '" + detectionPoint.getThreshold().getInterval().getDuration() + "'");

            if (detectionPoint.getThreshold().getInterval().getUnit() != null) {
              clauses
                  .add(Utils.THRESHOLD_INTERVAL_UNIT + " = '" + detectionPoint.getThreshold().getInterval().getUnit() + "'");
            }
          }
        }
      }
    }

    if(earliest != null) {
      clauses.add(Utils.TIMESTAMP + " >= '" + earliest.toString() + "'");
    }

    int i = 0;
    for(String clause : clauses) {
      sql += (i == 0) ? " WHERE " : " AND ";

      sql += clause;

      i++;
    }

    System.err.println("executing: " + sql);

    return sql;
  }


  public static boolean isInitializedProperly(Environment environment) {
    boolean initializedProperly = StringUtils.isNotBlank(environment.getProperty(INFLUXDB_CONNECTION_STRING)) &&
                                  StringUtils.isNotBlank(environment.getProperty(INFLUXDB_USERNAME)) &&
                                  StringUtils.isNotBlank(environment.getProperty(INFLUXDB_PASSWORD));

    return initializedProperly;
  }

  public static String getUninitializedMessage(Environment environment) {
    StringBuilder sb = new StringBuilder();

    Collection<String> setVariables = new ArrayList<>();
    Collection<String> missingVariables = new ArrayList<>();

    if (StringUtils.isBlank(environment.getProperty(INFLUXDB_CONNECTION_STRING))) {
      missingVariables.add(INFLUXDB_CONNECTION_STRING);
    } else {
      setVariables.add(INFLUXDB_CONNECTION_STRING);
    }

    if (StringUtils.isBlank(environment.getProperty(INFLUXDB_USERNAME))) {
      missingVariables.add(INFLUXDB_USERNAME);
    } else {
      setVariables.add(INFLUXDB_USERNAME);
    }

    if (StringUtils.isBlank(environment.getProperty(INFLUXDB_PASSWORD))) {
      missingVariables.add(INFLUXDB_PASSWORD);
    } else {
      setVariables.add(INFLUXDB_PASSWORD);
    }

    if (missingVariables.size() > 0) {
      sb.append("The following Environment variables must be set: ").append(missingVariables);

      if (setVariables.size() > 0) {
        sb.append(" (already set variables - ").append(setVariables).append(")");
      }
    }

    return sb.toString();
  }

}
