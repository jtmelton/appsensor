package org.owasp.appsensor.analysis;

import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.PriorityQueue;
import java.util.Queue;

import javax.inject.Inject;
import javax.inject.Named;

import org.hibernate.persister.entity.SingleTableEntityPersister;
import org.hibernate.type.TrueFalseType;
import org.jboss.logging.annotations.LoggingClass;
import org.joda.time.DateTime;
import org.joda.time.field.MillisDurationField;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.Threshold;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.analysis.EventAnalysisEngine;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.AttackStore;
import org.owasp.appsensor.core.storage.EventStore;
import org.owasp.appsensor.core.util.DateUtils;
import org.slf4j.Logger;
import org.springframework.expression.spel.ExpressionState;

import com.google.common.collect.Lists;

import antlr.collections.List;

/**
 * This is a statistical {@link Event} analysis engine,
 * and is an implementation of the Observer pattern.
 *
 * It is notified with implementations of the {@link Event} class.
 *
 * The implementation performs a simple analysis that watches the configured {@link Threshold} and
 * determines if it has been crossed. If so, an {@link Attack} is created and added to the
 * {@link AttackStore}.
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
@Loggable
public class DavidEventAnalysisEngine extends EventAnalysisEngine {

	private Logger logger;

	private ArrayList<Rule> rules;

	@Inject
	private AppSensorServer appSensorServer;

	/**
	 * This method determines whether an {@link Event} that has been added to the system
	 * has triggered a {@link Rule}. If so, an {@link Attack} is
	 * created and added to the system.
	 *
	 * @param event the {@link Event} that was added to the {@link EventStore}
	 */
	@Override
	public void analyze(Event triggerEvent) {
		// check if event is in the last Series of any Rules
		Collection<Rule> applicableRules = findApplicableRules(triggerEvent);

		if (applicableRules.size() > 0) {

			// find all events related to all applicable rules

			// find all events matching this event for this user
			// ASSUMPTION: this is in asc time order
			//existingEvents.addAll(appSensorServer.getEventStore().findEvents(criteria)); //TODO

			//set the end time for every rule
			DateTime ruleEndTime = DateUtils.fromString(triggerEvent.getTimestamp());

			for (Rule rule : applicableRules) {

				ArrayList<Event> existingEvents = new ArrayList<Event>();
				SearchCriteria criteria = new SearchCriteria().setUser(triggerEvent.getUser());

				for (DetectionPoint detectionPoint : rule.getAllDetectionPoints()) {
					criteria.setDetectionPoint(new DetectionPoint(detectionPoint.getCategory(), detectionPoint.getLabel())).
					setDetectionSystemIds(appSensorServer.getConfiguration().getRelatedDetectionSystems(triggerEvent.getDetectionSystem())).
					setEarliest(findMostRecentAttackTime(triggerEvent, rule).plus(1).toString());

					//existingEvents.addAll(appSensorServer.getEventStore().findEvents(criteria));
					for (Event event : appSensorServer.getEventStore().findEvents(criteria)) {
						if (existingEvents.contains(event) == false) {
							existingEvents.add(event);
						}
					}
				}

				Collections.sort(existingEvents, new EventComparator());
				Collections.reverse(existingEvents);

				boolean isRuleTriggered = true;

				DateTime ruleStartTime = ruleEndTime.minus(rule.getInterval().toMillis());
				DateTime lastExpressionStartTime = ruleEndTime.minus(rule.getLastExpression().getInterval().toMillis());

				//STEP 1: check last expression
				Expression lastExpression = rule.getLastExpression();
				//Queue<DPVInterval> lastIntervalList = new LinkedList<DPVInterval>();
				HashMap<DetectionPointVariable, DPVInterval> lastDpvIntervalMap = new HashMap<DetectionPointVariable, DPVInterval>();

				boolean isExpressionTriggered = false;

				lastDpvIntervalMap = (HashMap<DetectionPointVariable, DPVInterval>) createDetectionPointIntervalList(existingEvents, lastExpression.getDetectionPointVariables(), lastExpressionStartTime, ruleEndTime, true);

				/*
				for (DetectionPointVariable detectionPointVariable : lastExpression.getDetectionPointVariables()) {

					//boolean isDetectionPointTriggered = false;
					// todo: can we encapsulate this into a method
					lastDpvIntervalMap.put(detectionPointVariable, null);
					Queue<Event> eventQueue = new LinkedList<Event>();

					for (Event event : existingEvents) {

						//filter time
						if ((DateUtils.fromString(event.getTimestamp()).isAfter(lastExpressionStartTime)) &&
								(DateUtils.fromString(event.getTimestamp()).isBefore(ruleEndTime) || DateUtils.fromString(event.getTimestamp()).isEqual(ruleEndTime))) {

							//todo: make sure this is the correct function
							//if matches current detection point
							if (event.getDetectionPoint().typeAndThresholdMatches(detectionPointVariable.getDetectionPoint())) {

								eventQueue.add(event);

								//check if queue is full
								if (eventQueue.size() >= detectionPointVariable.getDetectionPoint().getThreshold().getCount()) {

									//is event interval less that threshold interval
									long queueIntervalInMillis = DateUtils.fromString(event.getTimestamp()).minus(
											DateUtils.fromString(eventQueue.peek().getTimestamp()).getMillis()).getMillis();
									//logger.debug("difference between " + DateUtils.fromString(event.getTimestamp()) + " and " + DateUtils.fromString(eventQueue.peek().getTimestamp()) + ": " + queueIntervalInMillis);
									if ( queueIntervalInMillis <= detectionPointVariable.getDetectionPoint().getThreshold().getInterval().toMillis()) {
										//lastIntervalList.add(new DPVInterval((int)(queueIntervalInMillis * 1000), "seconds", DateUtils.fromString(event.getTimestamp()), detectionPointVariable));
										// this constantly overwrites the value if multiple dpvintervals are found, but because we only want the last this works out perfectly
										lastDpvIntervalMap.put(detectionPointVariable, new DPVInterval((int)(queueIntervalInMillis), "milliseconds", DateUtils.fromString(event.getTimestamp()), detectionPointVariable));
										//isDetectionPointTriggered = true;
										break;
									}
									else {
										//pop
										eventQueue.poll();
									}
								}
							}
						}
					}
				}
				*/
				//evaluate last expression
				DateTime expressionTriggeredTime = evaluateExpression(lastExpression, lastDpvIntervalMap)[0];
				if (expressionTriggeredTime == null) {
					isRuleTriggered = false;
					break;
				}

				lastExpressionStartTime = expressionTriggeredTime;

				//STEP 2: Build intervalQueue
				Collections.sort(existingEvents, new EventComparator());

				Queue<DPVInterval> intervalList = new LinkedList<DPVInterval>();

				//get a list of the detection point variables from each expression (remove duplicates)
				ArrayList<DetectionPointVariable> dpvList = new ArrayList<DetectionPointVariable>();
				for (Expression expression : rule.getExpressions().subList(0, rule.getExpressions().size() - 1)) {

					for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {

						if (dpvList.contains(detectionPointVariable) == false) {
							dpvList.add(detectionPointVariable);
						}
					}
				}

				for (DetectionPointVariable detectionPointVariable : dpvList) {
					Queue<Event> eventQueue = new LinkedList<Event>();

					for (Event event : existingEvents) {

						// filter events by time and detection point
						if (DateUtils.fromString(event.getTimestamp()).isBefore(lastExpressionStartTime)) {
							//todo: make sure this is the correct function
							if (event.getDetectionPoint().typeAndThresholdMatches(detectionPointVariable.getDetectionPoint())) {

								eventQueue.add(event);

								//check if queue is full
								if (eventQueue.size() >= detectionPointVariable.getDetectionPoint().getThreshold().getCount()) {

									//is event interval less that threshold interval
									long queueIntervalInMillis = DateUtils.fromString(event.getTimestamp()).minus(
											DateUtils.fromString(eventQueue.peek().getTimestamp()).getMillis()).getMillis();
									if ( queueIntervalInMillis <= detectionPointVariable.getDetectionPoint().getThreshold().getInterval().toMillis()) {
										//todo: this approximation needs to be fixed, it will cause problems /hacked it
										intervalList.add(new DPVInterval((int)(queueIntervalInMillis), "milliseconds", DateUtils.fromString(eventQueue.peek().getTimestamp()), detectionPointVariable));
									}

									//pop
									eventQueue.poll();
								}
							}
						}
					}
				}

				//STEP 3: check each expression
				DateTime searchStartTime = ruleStartTime;

				for (Expression expression : rule.getExpressions().subList(0, rule.getExpressions().size() - 1)) {
					isExpressionTriggered = false;

					if (intervalList.isEmpty()) {
						isRuleTriggered = false;
						break;
					}

					//filter out intervals from intervalQueue that occurred before the searchStartTime
					DPVInterval peekInterval = intervalList.peek();

					while (peekInterval != null && peekInterval.getStartTime().isBefore(searchStartTime)) {
						intervalList.poll();
						peekInterval = intervalList.peek();
					}

					//create a new interval queue that filters out intervals for unrelated detection points
					ArrayList<DPVInterval> expressionIntervalList = new ArrayList<DPVInterval>();

					for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {

						for (DPVInterval interval : intervalList) {

							//todo: make sure this is the correct function
							//if matches current detection point
							if (interval.getDetectionPointVariable().getDetectionPoint().typeAndThresholdMatches(detectionPointVariable.getDetectionPoint())) {
								expressionIntervalList.add(interval);
							}
						}
					}

					for (DPVInterval possibleStartInterval : expressionIntervalList) {
						DateTime possibleExpressionStartTime = possibleStartInterval.getStartTime();
						DateTime possibleExpressionEndTime = possibleExpressionStartTime.plus(expression.getInterval().toMillis());

						if (possibleExpressionEndTime.isAfter(lastExpressionStartTime)) {
							possibleExpressionEndTime = lastExpressionStartTime;
						}

						//int count = 0;
						//boolean isPossibleExpressionTriggered = false;

						//create hash map to track which detection point variables had a detection point triggered
						HashMap<DetectionPointVariable, DPVInterval> dpvIntervalMap = new HashMap<DetectionPointVariable, DPVInterval>();

						for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {
							dpvIntervalMap.put(detectionPointVariable, null);
						}

						for (DPVInterval dpvInterval : expressionIntervalList) {

							if (dpvInterval.getEndTime().isBefore(possibleExpressionEndTime) ||
									dpvInterval.getEndTime().isEqual(possibleExpressionEndTime)) {

								if (dpvIntervalMap.get(dpvInterval.getDetectionPointVariable()) == null) {
									dpvIntervalMap.put(dpvInterval.getDetectionPointVariable(), dpvInterval);
									//count++;
								}
							}
							else if (dpvInterval.getStartTime().isAfter(possibleExpressionEndTime)) {
								//isPossibleExpressionTriggered = false;
								break;
							}
							else {
								//dpvInterval starts within the possible window, but finishes outside of it. Do nothing.
							}

							/*if (count == expression.getDetectionPointVariables().size()) {
								//we have filled the map!
								isPossibleExpressionTriggered = true;
								break;
							}*/
						}

						DateTime expressionEndTime = evaluateExpression(expression, dpvIntervalMap)[1];

						if (expressionEndTime != null) {
							isExpressionTriggered = true;
							searchStartTime = expressionEndTime;

							//find the latest time in dpv interval mapping
							/*
							for (DetectionPointVariable detectionPointVariable : dpvIntervalMap.keySet()) {

								if (dpvIntervalMap.get(detectionPointVariable) != null && dpvIntervalMap.get(detectionPointVariable).getEndTime().isAfter(searchStartTime)) {
									searchStartTime = dpvIntervalMap.get(detectionPointVariable).getEndTime();
								}
							}
							*/

							break;
						}
					}

					if (isExpressionTriggered == false) {
						isRuleTriggered = false;
						break;
					}
				}

				if (isRuleTriggered == true) {
					//generate attack
					logger.debug("ATTACK!!!");
					logger.info("Violation Observed for user <" + triggerEvent.getUser().getUsername() + "> on rule <" + rule.getName() + "> - storing attack");

					//have determined this event triggers attack
					//ensure appropriate detection point is being used (associated responses, etc.)
					Attack attack = new Attack();
					attack.setUser(new User(triggerEvent.getUser().getUsername() + "R"));
					attack.setRule(rule.getName());
					attack.setTimestamp(triggerEvent.getTimestamp());
					attack.setDetectionPoint(rule.getLastExpression().getDetectionPoints().get(0));
					attack.setDetectionSystem(triggerEvent.getDetectionSystem());
					attack.setResource(triggerEvent.getResource());

					appSensorServer.getAttackStore().addAttack(attack);
				}
			}
		}
	}


	/**
	 * Find most recent {@link Attack} matching the given {@link Event} {@link User}, {@link DetectionPoint}
	 * matching the currently configured detection point (supporting multiple detection points per label),
	 * detection system and find it's timestamp.
	 *
	 * The {@link Event} should only be counted if they've occurred after the most recent {@link Attack}.
	 *
	 * @param event {@link Event} to use to find matching {@link Attack}s
	 * @param configuredDetectionPoint {@link DetectionPoint} to use to find matching {@link Attack}s
	 * @return timestamp representing last matching {@link Attack}, or -1L if not found
	 */
	protected DateTime findMostRecentAttackTime(Event event, Rule rule) {
		DateTime newest = DateUtils.epoch();

		SearchCriteria criteria = new SearchCriteria().
				setUser(new User(event.getUser().getUsername() + "R")).
				setDetectionSystemIds(appSensorServer.getConfiguration().getRelatedDetectionSystems(event.getDetectionSystem()));

		Collection<Attack> attacks = appSensorServer.getAttackStore().findAttacks(criteria);

		for (Attack attack : attacks) {
			if (attack.getRule() != null && attack.getRule().equals(rule.getName())) {
				if (DateUtils.fromString(attack.getTimestamp()).isAfter(newest)) {
					newest = DateUtils.fromString(attack.getTimestamp());
				}
			}
		}

		return newest;
	}

	protected ArrayList<Rule> findApplicableRules(Event event) {
		ArrayList<Rule> matches = new ArrayList<Rule>();

		for (Rule rule : rules) {
			if (rule.checkLastExpressionForDetectionPoint(event.getDetectionPoint())) {
				matches.add(rule);
			}
		}

		return matches;
	}

	public void addRule(Rule rule) {
		if (rules == null) {
			rules = new ArrayList<Rule>();
		}
		rules.add(rule);
		logger.debug("Adding rule. Exps: " + rule.getExpressions().size() + " DPs: " + rule.getAllDetectionPoints().size());
		logger.debug("Total rules: " + rules.size());
	}

	public void removeRule(Rule rule) {
		if (rules != null) {
			rules.remove(rule);
		}
	}

	public void clearRules() {
		if (rules != null) {
			rules.clear();
			logger.debug("Clearing rules. Number of rules: " + rules.size());
		}
	}

	protected class EventComparator implements Comparator<Event> {

		public int compare(Event e1, Event e2) {
			if (DateUtils.fromString(e1.getTimestamp()).isBefore(DateUtils.fromString(e2.getTimestamp()))) {
				return -1;
			}
			else if (DateUtils.fromString(e1.getTimestamp()).isAfter(DateUtils.fromString(e2.getTimestamp()))) {
				return 1;
			}
			else {
				return 0;
			}
		}
	}

	// todo: rewrite this function, compare to both existing functions
	///*
	protected Object createDetectionPointIntervalList(ArrayList<Event> events, ArrayList<DetectionPointVariable> dpvs, DateTime start, DateTime end, boolean isLastExpression) {
		Object dpiList = null;

		if (isLastExpression) {
			dpiList = new HashMap<DetectionPointVariable, DPVInterval>();
		}
		else {
			dpiList = new ArrayList<DPVInterval>();
		}

		for (DetectionPointVariable detectionPointVariable : dpvs) {
			if (isLastExpression) {
				((HashMap<DetectionPointVariable, DPVInterval>)dpiList).put(detectionPointVariable, null);
			}

			Queue<Event> eventQueue = new LinkedList<Event>();
			for (Event event : events) {

				//filter time & detection point
				//todo: checking if the end is equal is for last expression only
				if ((DateUtils.fromString(event.getTimestamp()).isAfter(start)) &&
						(DateUtils.fromString(event.getTimestamp()).isBefore(end) || DateUtils.fromString(event.getTimestamp()).isEqual(end))) {
					//todo: make sure this is the correct function
					if (event.getDetectionPoint().typeAndThresholdMatches(detectionPointVariable.getDetectionPoint())) {

						eventQueue.add(event);

						//check if queue is full
						if (eventQueue.size() >= detectionPointVariable.getDetectionPoint().getThreshold().getCount()) {
							//is event interval less that threshold interval
							long queueIntervalInMillis = DateUtils.fromString(event.getTimestamp()).minus(DateUtils.fromString(eventQueue.peek().getTimestamp()).getMillis()).getMillis();

							if ( queueIntervalInMillis <= detectionPointVariable.getDetectionPoint().getThreshold().getInterval().toMillis()) {
								DPVInterval dpvi =  new DPVInterval((int)(queueIntervalInMillis), "milliseconds", DateUtils.fromString(event.getTimestamp()), detectionPointVariable);

								if (isLastExpression) {
									((HashMap<DetectionPointVariable, DPVInterval>)dpiList).put(detectionPointVariable, dpvi);
								}
								else {
									((ArrayList<DPVInterval>)dpiList).add(dpvi);
								}

								break;
							}
							else {
								eventQueue.poll();
							}
						}
					}
				}
			}
		}

		return dpiList;
	}
	//*/

	protected DateTime[] evaluateExpression(Expression expression, HashMap<DetectionPointVariable, DPVInterval> dpvIntervalMap) {
		//discover or clauses
		ArrayList<ArrayList<DetectionPointVariable>> clauses = new ArrayList<ArrayList<DetectionPointVariable>>();
		clauses.add(new ArrayList<DetectionPointVariable>());
		int numClauses = 0;
		for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {
			if (detectionPointVariable.getBooleanOperator() == DetectionPointVariable.BOOLEAN_OPERATOR_OR ||
					detectionPointVariable.getBooleanOperator() == DetectionPointVariable.BOOLEAN_OPERATOR_OR_NOT) {
				numClauses++;
				clauses.add(new ArrayList<DetectionPointVariable>());
			}
			clauses.get(numClauses).add(detectionPointVariable);
		}


		DateTime expEarliest = null;
		DateTime expLatest = null;

		for (ArrayList<DetectionPointVariable> clause : clauses) {
			boolean isClauseTrue = true;
			DateTime clauseEarliest = null;
			DateTime clauseLatest = null;

			for (DetectionPointVariable dp : clause) {
				DPVInterval interval = dpvIntervalMap.get(dp);

				//if true
				if (dp.getBooleanOperator() == DetectionPointVariable.BOOLEAN_OPERATOR_AND && interval != null ||
						dp.getBooleanOperator() == DetectionPointVariable.BOOLEAN_OPERATOR_AND_NOT && interval == null ||
						dp.getBooleanOperator() == DetectionPointVariable.BOOLEAN_OPERATOR_OR && interval != null ||
						dp.getBooleanOperator() == DetectionPointVariable.BOOLEAN_OPERATOR_OR_NOT && interval == null) {

					if (interval != null) {
						if (clauseEarliest == null || interval.getStartTime().isBefore(clauseEarliest)) {
							clauseEarliest = interval.getStartTime();
						}
						if (clauseLatest == null || interval.getEndTime().isAfter(clauseLatest)) {
							clauseLatest = interval.getEndTime();
						}
					}
				}
				else {
					isClauseTrue = false;
				}
			}

			if (isClauseTrue) {
				//set expEarliest, expLatest
				if (expEarliest == null || clauseEarliest.isAfter(expEarliest)) {
					expEarliest = clauseEarliest;
				}
				if (expLatest == null || clauseLatest.isBefore(expLatest)) {
					expLatest = clauseLatest;
				}
			}
		}

		DateTime[] results = {expEarliest, expLatest};

		return results;
	}

	/*
	protected DateTime findExpressionStart(HashMap<DetectionPointVariable, DPVInterval> map, Expression expression) {
		DateTime latest = null;
		DateTime earliestInOr = null;

		for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {
			if (detectionPointVariable.getBooleanOperator() == DetectionPointVariable.BOOLEAN_OPERATOR_OR ||
					detectionPointVariable.getBooleanOperator() == DetectionPointVariable.BOOLEAN_OPERATOR_OR_NOT) {
				if (latest == null || (earliestInOr != null && earliestInOr.isAfter(latest))) {
					latest = earliestInOr;
				}
				earliestInOr = null;
			}

			if (map.get(detectionPointVariable) != null && (earliestInOr == null || map.get(detectionPointVariable).getStartTime().isBefore(earliestInOr))) {
				earliestInOr = map.get(detectionPointVariable).getStartTime();
			}
		}

		if (latest == null) {
			latest = earliestInOr;
		}

		return latest;
	}


	protected boolean evaluateExpression(Expression expression, HashMap<DetectionPointVariable, DPVInterval> dpvIntervalMap) {
		boolean result = true;

		for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {
			Integer booleanOperator = detectionPointVariable.getBooleanOperator();

			if((booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_AND && dpvIntervalMap.get(detectionPointVariable) == null) || (
					booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_AND_NOT && dpvIntervalMap.get(detectionPointVariable) != null)) {
				result = false;
			}

			else if (booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_OR ||
					booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_OR_NOT) {

				if (result == true) {
					return result;
				}
				else {

					if((booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_OR && dpvIntervalMap.get(detectionPointVariable) != null) || (
							booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_OR_NOT && dpvIntervalMap.get(detectionPointVariable) == null)) {
						result = true;
					}
				}
			}
		}

		return result;
	}

	protected DateTime evaluateLastExpression(Expression expression, HashMap<DetectionPointVariable, DPVInterval> dpvIntervalMap) {
		boolean result = true;
		DateTime latestOrClauseStart = null;
		DateTime earliestInOrClause = null;

		evaluateExpression(expression, dpvIntervalMap);

		for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {
			Integer booleanOperator = detectionPointVariable.getBooleanOperator();
			DPVInterval interval = dpvIntervalMap.get(detectionPointVariable);

			//and fail
			if((booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_AND && interval == null) || (
					booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_AND_NOT && interval != null)) {
				result = false;
			}
			//or
			else if (booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_OR ||
					booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_OR_NOT) {

				if (result == true) {
					if (latestOrClauseStart == null || earliestInOrClause.isAfter(latestOrClauseStart)) {
						latestOrClauseStart = earliestInOrClause;
					}
				}

				earliestInOrClause = null;
				if((booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_OR && interval != null) || (
						booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_OR_NOT && interval == null)) {
					result = true;
					earliestInOrClause = interval.getStartTime();
				}
				else {
					earliestInOrClause = null;
				}

			}
			//and true
			else {
				if (interval != null) {
					if (earliestInOrClause == null || (result == true && interval.getStartTime().isBefore(earliestInOrClause))) {
						earliestInOrClause = interval.getStartTime();
					}
				}
			}
		}

		if (result == true) {
			if (latestOrClauseStart != null && earliestInOrClause != null && earliestInOrClause.isAfter(latestOrClauseStart)) {
				latestOrClauseStart = earliestInOrClause;
			}
			else if (latestOrClauseStart == null) {
				latestOrClauseStart = earliestInOrClause;
			}
		}

		if (latestOrClauseStart != null) {
			return latestOrClauseStart;
		}
		else {
			return null;
		}
	}

	protected DateTime evaluateOtherExpression(Expression expression, HashMap<DetectionPointVariable, DPVInterval> dpvIntervalMap) {
		boolean result = true;
		DateTime earliestOrClauseStart = null;
		DateTime latestInOrClause = null;

		for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {
			Integer booleanOperator = detectionPointVariable.getBooleanOperator();
			DPVInterval interval = dpvIntervalMap.get(detectionPointVariable);

			//and fail
			if((booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_AND && interval == null) || (
					booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_AND_NOT && interval != null)) {
				result = false;
			}
			//or
			else if (booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_OR ||
					booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_OR_NOT) {

				if (result == true) {
					if (earliestOrClauseStart == null || latestInOrClause.isBefore(earliestOrClauseStart)) {
						earliestOrClauseStart = latestInOrClause;
					}
				}

				if((booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_OR && interval != null) || (
						booleanOperator == DetectionPointVariable.BOOLEAN_OPERATOR_OR_NOT && interval == null)) {
					result = true;
					latestInOrClause = interval.getEndTime();
				}
				else {
					latestInOrClause = null;
				}

			}
			//and true
			else {
				if (interval != null) {
					if (latestInOrClause == null || (result == true && interval.getEndTime().isAfter(latestInOrClause))) {
						latestInOrClause = interval.getEndTime();
					}
				}
			}
		}

		if (result == true) {
			if (earliestOrClauseStart != null && latestInOrClause != null && latestInOrClause.isBefore(earliestOrClauseStart)) {
				earliestOrClauseStart = latestInOrClause;
			}
			else if (earliestOrClauseStart == null) {
				earliestOrClauseStart = latestInOrClause;
			}
		}

		if (earliestOrClauseStart != null) {
			return latestInOrClause;
		}
		else {
			return null;
		}
	}
	*/
}
