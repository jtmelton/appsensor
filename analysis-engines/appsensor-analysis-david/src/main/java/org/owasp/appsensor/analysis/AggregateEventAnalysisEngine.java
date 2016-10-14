package org.owasp.appsensor.analysis;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Queue;

import javax.inject.Inject;
import javax.inject.Named;

import org.joda.time.DateTime;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.analysis.EventAnalysisEngine;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.EventStore;
import org.owasp.appsensor.core.util.DateUtils;
import org.slf4j.Logger;

/**
 * This is a rule based {@link Event} analysis engine.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */
@Named
@Loggable
public class AggregateEventAnalysisEngine extends EventAnalysisEngine {

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
		// check if triggerEvent matches the detection point in the last expression of any Rules and returns all matches
		Collection<Rule> applicableRules = getApplicableRules(triggerEvent);

		if (applicableRules.size() > 0) {
			DateTime ruleEndTime = DateUtils.fromString(triggerEvent.getTimestamp());

			for (Rule rule : applicableRules) {
				DateTime ruleStartTime = ruleEndTime.minus(rule.getInterval().toMillis());
				DateTime lastExpressionStartTime = ruleEndTime.minus(rule.getLastExpression().getInterval().toMillis());
				ArrayList<Event> events = getApplicableEvents(triggerEvent, rule);

				// checks whether the last expression of the rule was triggered, if not stop evaluating this rule
				lastExpressionStartTime = checkLastExpression(rule.getLastExpression(), events, lastExpressionStartTime, ruleEndTime);

				if (lastExpressionStartTime == null) {
					break;
				}

				// build a queue of dpv intervals in chronological order
				Queue<DPVInterval> intervalQueue = buildIntervalQueue(events, rule.getExpressions(), ruleStartTime, lastExpressionStartTime);

				// using the interval queue, check each expression. If they have all evaluate to true, then the rule has been triggered
				if (checkAllExpressions(rule, intervalQueue, ruleStartTime, lastExpressionStartTime)) {
					logger.info("Violation Observed for user <" + triggerEvent.getUser().getUsername() + "> on rule <" + rule.getName() + "> - storing attack");

					Attack attack = new Attack();
					// todo: hack to make attack from a rule. Add an "R" to the end of the user
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

	protected ArrayList<Rule> getApplicableRules(Event event) {
		ArrayList<Rule> matches = new ArrayList<Rule>();

		for (Rule rule : rules) {
			if (rule.checkLastExpressionForDetectionPoint(event.getDetectionPoint())) {
				matches.add(rule);
			}
		}

		return matches;
	}

	protected ArrayList<Event> getApplicableEvents(Event triggerEvent, Rule rule) {
		ArrayList<Event> events = new ArrayList<Event>();

		// set user and earliest time for search
		SearchCriteria criteria = new SearchCriteria().
				setUser(triggerEvent.getUser()).
				setEarliest(findMostRecentAttackTime(triggerEvent, rule).plus(1).toString());

		for (DetectionPoint detectionPoint : rule.getAllDetectionPoints()) {
			// set the detection point and system IDS
			criteria.
				setDetectionPoint(new DetectionPoint(detectionPoint.getCategory(), detectionPoint.getLabel())).
				setDetectionSystemIds(appSensorServer.getConfiguration().getRelatedDetectionSystems(triggerEvent.getDetectionSystem()));

			for (Event event : appSensorServer.getEventStore().findEvents(criteria)) {
				if (events.contains(event) == false) {
					events.add(event);
				}
			}
		}

		// sorts events in chronological order
		Collections.sort(events, new EventComparator());

		return events;
	}

	// TODO: will be changed one hack gets fixed
	// borrowed and tweaked from the Reference implementation
	protected DateTime findMostRecentAttackTime(Event event, Rule rule) {
		DateTime newest = DateUtils.epoch();

		// current hack around lack of support around rules adds "R" to the end of the user
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

	/* this function checks whether the last expression was triggered by mapping each of the detection points
	 * in the last expression to the latest occurring time they were triggered (if at all) and then evaluating
	 * the results
	 */
	protected DateTime checkLastExpression(Expression expression, ArrayList<Event> events, DateTime start, DateTime end) {
		HashMap<DetectionPointVariable, DPVInterval> dpiMap = new HashMap<DetectionPointVariable, DPVInterval>();

		// create map of detection point intervals
		for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {
			dpiMap.put(detectionPointVariable, null);

			Queue<Event> eventQueue = new LinkedList<Event>();

			for (Event event : events) {

				// filter events by time and detection point
				DateTime eventTime = DateUtils.fromString(event.getTimestamp());
				if (eventTime.isAfter(start) && (eventTime.isBefore(end) || eventTime.isEqual(end))) {
					if (event.getDetectionPoint().typeAndThresholdMatches(detectionPointVariable.getDetectionPoint())) {

						eventQueue.add(event);

						// check if queue is full
						if (eventQueue.size() >= detectionPointVariable.getDetectionPoint().getThreshold().getCount()) {

							// is the queue interval is less than threshold interval
							DateTime queueStartTime = DateUtils.fromString(eventQueue.peek().getTimestamp());
							long queueIntervalInMillis = eventTime.minus(queueStartTime.getMillis()).getMillis();

							if ( queueIntervalInMillis <= detectionPointVariable.getDetectionPoint().getThreshold().getInterval().toMillis()) {
								DPVInterval	dpvi = new DPVInterval((int)queueIntervalInMillis, "milliseconds", queueStartTime, detectionPointVariable);
								dpiMap.put(detectionPointVariable, dpvi);
							}

							eventQueue.poll();
						}
					}
				}
			}
		}

		// evaluate last expression
		return evaluateExpression(expression, dpiMap)[0];
	}

	/*
	 * this function builds a Queue<DPVInterval> of all events to be used later when evaluated the remaining expressions of the rule.
	 */
	protected Queue<DPVInterval> buildIntervalQueue(ArrayList<Event> events, ArrayList<Expression> expressions, DateTime start, DateTime end) {
		// get a list of the detection point variables from each expression (remove duplicates)
		Queue<DPVInterval> dpiQueue = new LinkedList<DPVInterval>();
		ArrayList<DetectionPointVariable> dpvList = new ArrayList<DetectionPointVariable>();

		for (Expression expression : expressions.subList(0, expressions.size() - 1)) {

			for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {

				if (dpvList.contains(detectionPointVariable) == false) {
					dpvList.add(detectionPointVariable);
				}
			}
		}

		for (DetectionPointVariable detectionPointVariable : dpvList) {
			Queue<Event> eventQueue = new LinkedList<Event>();

			for (Event event : events) {

				// filter events by time and detection point
				DateTime eventTime = DateUtils.fromString(event.getTimestamp());
				if (eventTime.isBefore(end)) {
						if (event.getDetectionPoint().typeAndThresholdMatches(detectionPointVariable.getDetectionPoint())) {

						eventQueue.add(event);

						// check if queue is full
						if (eventQueue.size() >= detectionPointVariable.getDetectionPoint().getThreshold().getCount()) {

							// is event interval less that threshold interval
							DateTime queueStartTime = DateUtils.fromString(eventQueue.peek().getTimestamp());
							long queueIntervalInMillis = eventTime.minus(queueStartTime.getMillis()).getMillis();

							if ( queueIntervalInMillis <= detectionPointVariable.getDetectionPoint().getThreshold().getInterval().toMillis()) {
								DPVInterval	dpvi = new DPVInterval((int)(queueIntervalInMillis), "milliseconds", queueStartTime, detectionPointVariable);
								dpiQueue.add(dpvi);
							}

							eventQueue.poll();
						}
					}
				}
			}
		}

		return dpiQueue;
	}

	/*
	 * this function checks each remaining rule to see whether that evaluate to true or not. It does so by starting with the first expression
	 * and "sliding" the expression window through the possible start points and checking whether the expression was triggered within that window.
	 */
	protected boolean checkAllExpressions(Rule rule, Queue<DPVInterval> intervalList, DateTime searchStartTime, DateTime lastExpressionStartTime) {
		boolean isRuleTriggered = true;
		boolean isExpressionTriggered = false;

		for (Expression expression : rule.getExpressions().subList(0, rule.getExpressions().size() - 1)) {
			isExpressionTriggered = false;

			if (intervalList.isEmpty()) {
				isRuleTriggered = false;
				break;
			}

			// filter out intervals from intervalQueue that occurred before the searchStartTime
			DPVInterval peekInterval = intervalList.peek();

			while (peekInterval != null && peekInterval.getStartTime().isBefore(searchStartTime)) {
				intervalList.poll();
				peekInterval = intervalList.peek();
			}

			// create a new interval queue that filters out intervals for unrelated detection points
			// the new interval queue is also used as a copy for sliding the expression window
			ArrayList<DPVInterval> expressionIntervalList = new ArrayList<DPVInterval>();

			for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {

				for (DPVInterval interval : intervalList) {

					// if matches current detection point
					if (interval.getDetectionPointVariable().getDetectionPoint().typeAndThresholdMatches(detectionPointVariable.getDetectionPoint())) {
						expressionIntervalList.add(interval);
					}
				}
			}

			// check each possible start time for the expression - i.e. slide the expression window
			for (DPVInterval possibleStartInterval : expressionIntervalList) {
				DateTime possibleExpressionStartTime = possibleStartInterval.getStartTime();
				DateTime possibleExpressionEndTime = possibleExpressionStartTime.plus(expression.getInterval().toMillis());

				if (possibleExpressionEndTime.isAfter(lastExpressionStartTime)) {
					possibleExpressionEndTime = lastExpressionStartTime;
				}

				// create hash map to track which detection point variables had a detection point triggered
				HashMap<DetectionPointVariable, DPVInterval> dpvIntervalMap = new HashMap<DetectionPointVariable, DPVInterval>();

				for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {
					dpvIntervalMap.put(detectionPointVariable, null);
				}

				for (DPVInterval dpvInterval : expressionIntervalList) {

					if (dpvInterval.getEndTime().isBefore(possibleExpressionEndTime) ||
							dpvInterval.getEndTime().isEqual(possibleExpressionEndTime)) {

						if (dpvIntervalMap.get(dpvInterval.getDetectionPointVariable()) == null) {
							dpvIntervalMap.put(dpvInterval.getDetectionPointVariable(), dpvInterval);
						}
					}
					else if (dpvInterval.getStartTime().isAfter(possibleExpressionEndTime)) {
						// there are no more dpvIntervals that start within the expressions possible interval
						break;
					}
					else {
						// dpvInterval starts within the possible window, but finishes outside of it. Do nothing.
					}

				}

				// check the expression at each step along the way. This will allow it to determine when exactly an
				// expression was triggered. Has interesting implications for the "NOT" operator
				DateTime expressionEndTime = evaluateExpression(expression, dpvIntervalMap)[1];

				if (expressionEndTime != null) {
					isExpressionTriggered = true;
					searchStartTime = expressionEndTime;

					break;
				}
			}

			if (isExpressionTriggered == false) {
				isRuleTriggered = false;
				break;
			}
		}

		return isRuleTriggered;
	}

	/*
	 * this function takes a mapping of detection points to intervals to determine whether an expression has been triggered.
	 * if the expression has been triggered then the function will return an array containing the start and end of the expression.
	 * these are used to determine the start or end of the windows for other expressions.
	 * if the expression has not been triggered then the funfciont will return null.
	 */
	protected DateTime[] evaluateExpression(Expression expression, HashMap<DetectionPointVariable, DPVInterval> dpvIntervalMap) {
		/*
		 * to correctly identify the start and end of an expression each "clause", variables divided by "OR" operators, must
		 * be checked.
		 */
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
}


	// pretty hacky function to generate DPVI lists for both contexts
	/*
	protected Object createDPVIList(ArrayList<Event> events, ArrayList<DetectionPointVariable> dpvs, DateTime start, DateTime end, boolean isLastExpression) {
		Object dpiList;

		if (isLastExpression) {
			dpiList = new HashMap<DetectionPointVariable, DPVInterval>();
		}
		else {
			dpiList = new LinkedList<DPVInterval>();
		}

		for (DetectionPointVariable detectionPointVariable : dpvs) {
			if (isLastExpression) {
				((HashMap<DetectionPointVariable, DPVInterval>)dpiList).put(detectionPointVariable, null);
			}

			Queue<Event> eventQueue = new LinkedList<Event>();

			for (Event event : events) {

				// filter events by time and detection point
				if ((!isLastExpression && DateUtils.fromString(event.getTimestamp()).isBefore(end)) ||
						(isLastExpression && DateUtils.fromString(event.getTimestamp()).isAfter(start) && (DateUtils.fromString(event.getTimestamp()).isBefore(end) || DateUtils.fromString(event.getTimestamp()).isEqual(end)))) {					//todo: make sure this is the correct function
					if (event.getDetectionPoint().typeAndThresholdMatches(detectionPointVariable.getDetectionPoint())) {

						eventQueue.add(event);

						//check if queue is full
						if (eventQueue.size() >= detectionPointVariable.getDetectionPoint().getThreshold().getCount()) {

							//is event interval less that threshold interval
							long queueIntervalInMillis = DateUtils.fromString(event.getTimestamp()).minus(
									DateUtils.fromString(eventQueue.peek().getTimestamp()).getMillis()).getMillis();
							if ( queueIntervalInMillis <= detectionPointVariable.getDetectionPoint().getThreshold().getInterval().toMillis()) {
								//todo: this approximation needs to be fixed, it will cause problems /hacked it
								DPVInterval	dpvi = new DPVInterval((int)(queueIntervalInMillis), "milliseconds", DateUtils.fromString(eventQueue.peek().getTimestamp()), detectionPointVariable);

								if (isLastExpression) {
									((HashMap<DetectionPointVariable, DPVInterval>)dpiList).put(detectionPointVariable, dpvi);
								}
								else {
									((LinkedList<DPVInterval>)dpiList).add(new DPVInterval((int)(queueIntervalInMillis), "milliseconds", DateUtils.fromString(eventQueue.peek().getTimestamp()), detectionPointVariable));
								}
							}

							//pop
							eventQueue.poll();
						}
					}
				}
			}
		}

		return dpiList;
	}
	*/
