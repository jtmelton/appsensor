package org.owasp.appsensor.storage.influxdb;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Named;

import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.dto.Point;
import org.influxdb.dto.Query;
import org.influxdb.dto.QueryResult;
import org.joda.time.DateTime;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.rule.Rule;
import org.owasp.appsensor.core.storage.ResponseStore;
import org.owasp.appsensor.core.util.DateUtils;
import org.slf4j.Logger;
import org.springframework.core.env.Environment;

import com.google.common.base.Preconditions;
import com.google.gson.Gson;

/**
 * Created by john.melton on 3/10/16.
 */
@Named
@Loggable
public class InfluxDbResponseStore extends ResponseStore {

  private Logger logger;

  private InfluxDB influxDB;

  private final Gson gson = new Gson();
  private boolean initializedProperly = true;

  @Inject
  private Environment environment;

  /**
   * {@inheritDoc}
   */
  @Override
  public void addResponse(Response response) {
    logger.warn("Security response " + response.getAction() + " triggered for user: " + response.getUser().getUsername());

    Point.Builder builder = Point.measurement(Utils.RESPONSES)
        .time(DateUtils.fromString(response.getTimestamp()).getMillis(), TimeUnit.MILLISECONDS)
        .field(Utils.RESPONSE_ACTION, response.getAction())
        .tag(Utils.USERNAME, response.getUser().getUsername())
        .tag(Utils.TIMESTAMP, response.getTimestamp())
        .tag(Utils.DETECTION_SYSTEM, response.getDetectionSystem().getDetectionSystemId());

    if(response.getInterval() != null) {
      builder = builder
          .tag(Utils.RESPONSE_INTERVAL_DURATION, String.valueOf(response.getInterval().getDuration()))
          .tag(Utils.RESPONSE_INTERVAL_UNIT, response.getInterval().getUnit());
    }

    Point point = builder.tag(Utils.RESPONSE_ACTION, response.getAction())
        .field(Utils.JSON_CONTENT, gson.toJson(response))
        .build();

    influxDB.write(Utils.DATABASE, "default", point);

    super.notifyListeners(response);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Collection<Response> findResponses(SearchCriteria criteria) {
    Preconditions.checkNotNull(criteria, "criteria must be non-null");

    Collection<Response> matches = new ArrayList<>();

    User user = criteria.getUser();
    DetectionPoint detectionPoint = criteria.getDetectionPoint();
    Rule rule = criteria.getRule();
    Collection<String> detectionSystemIds = criteria.getDetectionSystemIds();
    DateTime earliest = DateUtils.fromString(criteria.getEarliest());

    String influxQL = Utils.constructInfluxQL(Utils.RESPONSES, user, detectionPoint, rule, detectionSystemIds, earliest, Utils.QueryMode.CONSIDER_THRESHOLDS);

    Query query = new Query(influxQL, Utils.DATABASE);

    QueryResult results = influxDB.query(query);

    for(QueryResult.Result result : results.getResults()) {
      if(result == null || result.getSeries() == null) {
        continue;
      }

      for(QueryResult.Series series : result.getSeries()) {
        if(series == null || series.getValues() == null) {
          continue;
        }

        for(List<Object> record : series.getValues()) {
          if(record == null) {
            continue;
          }

          matches.add( gson.fromJson( Utils.getValue(Utils.JSON_CONTENT, series, record), Response.class ) );
        }

      }
    }

    return matches;
  }

  private void ensureInitialized() {
    if(! initializedProperly) {
      throw new IllegalStateException(Utils.getUninitializedMessage(environment));
    }
  }

  @PostConstruct
  public void ensureEnvironmentVariablesSet() {
    initializedProperly = Utils.isInitializedProperly(environment);

    if(initializedProperly) {
      influxDB = InfluxDBFactory.connect(environment.getProperty(Utils.INFLUXDB_CONNECTION_STRING),
                                         environment.getProperty(Utils.INFLUXDB_USERNAME),
                                         environment.getProperty(Utils.INFLUXDB_PASSWORD));

      Utils.createDatabaseIfNotExists(influxDB);
    } else {
      String msg = Utils.getUninitializedMessage(environment);

      if(logger != null) {
        logger.error(msg);
      } else {
        System.err.println(msg);
      }
    }
  }

}
