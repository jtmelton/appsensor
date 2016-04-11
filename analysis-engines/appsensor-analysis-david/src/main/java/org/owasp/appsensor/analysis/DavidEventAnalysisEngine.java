package org.owasp.appsensor.analysis;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.PriorityQueue;
import java.util.Queue;

import javax.inject.Inject;
import javax.inject.Named;

import org.hibernate.persister.entity.SingleTableEntityPersister;
import org.joda.time.DateTime;
import org.joda.time.field.MillisDurationField;
import org.mockito.internal.matchers.And;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Interval;
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
	 * This method analyzes statistical {@link Event}s that are added to the system and 
	 * detects if the configured {@link Threshold} has been crossed. If so, an {@link Attack} is 
	 * created and added to the system.
	 * 
	 * @param event the {@link Event} that was added to the {@link EventStore}
	 */
	@Override
	public void analyze(Event triggerEvent) {
		// check if event is in the last Series of any Rules
		Collection<Rule> applicableRules = findApplicableRules(triggerEvent);
		
		if (applicableRules.size() > 0) {
			Collection<Event> existingEvents = null;
			SearchCriteria criteria = new SearchCriteria().setUser(triggerEvent.getUser());
			
			// todo: may want to check if findEvents returns null, and remove rule from consideration
			
			// find all events related to all applicable rules
			for (Rule rule : applicableRules) {
				for (DetectionPoint detectionPoint : rule.getAllDetectionPoints()) {
					criteria.addDetectionPoint(detectionPoint).
					setDetectionSystemIds(appSensorServer.getConfiguration().getRelatedDetectionSystems(triggerEvent.getDetectionSystem()));
				}			
			}
			
			// find all events matching this event for this user
			// ASSUMPTION: this is in asc time order
			existingEvents.addAll(appSensorServer.getEventStore().findEvents(criteria));
			
			//set the end time for every rule
			DateTime ruleEndTime = DateUtils.fromString(triggerEvent.getTimestamp());
			
			for (Rule rule : applicableRules) {
				
				boolean isRuleTriggered = true;
				
				DateTime ruleStartTime = ruleEndTime.minusMillis((int)rule.getInterval().toMillis());
				DateTime lastExpressionStartTime = ruleEndTime.minusMillis((int)rule.getLastExpression().getInterval().toMillis());
				
				//STEP 1: check last expression
				Expression lastExpression = rule.getLastExpression();
				
				boolean isExpressionTriggered = false;
				
				for (DetectionPointVariable detectionPointVariable : lastExpression.getDetectionPointVariables()) {

					boolean isDetectionPointTriggered = false;
					Queue<Event> eventQueue = new LinkedList<Event>();
					
					for (Event event : existingEvents) {
						
						//filter time
						if (DateUtils.fromString(event.getTimestamp()).isAfter(lastExpressionStartTime) &&
								DateUtils.fromString(event.getTimestamp()).isBefore(ruleEndTime)) {
							
							//todo: make sure this is the correct function
							//if matches current detection point
							if (event.getDetectionPoint().typeAndThresholdMatches(detectionPointVariable.getDetectionPoint())) {
								
								eventQueue.add(event);
								
								//check if queue is full 
								if (eventQueue.size() >= detectionPointVariable.getDetectionPoint().getThreshold().getCount()) {
									
									//is event interval less that threshold interval
									long queueIntervalInMillis = DateUtils.fromString(event.getTimestamp()).minusMillis(
											(int)DateUtils.fromString(eventQueue.peek().getTimestamp()).getMillis()).getMillis();
									if ( queueIntervalInMillis <= detectionPointVariable.getDetectionPoint().getThreshold().getInterval().toMillis()) {

										isDetectionPointTriggered = true;
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
					
					if (isDetectionPointTriggered == false) {
						isExpressionTriggered = false;
						break;
					}
				}
				
				if (isExpressionTriggered == false) {
					isRuleTriggered = false;
					break;
				}	
				
				ArrayList<Expression> expressions = rule.getExpressions();
				expressions.remove(expressions.size() - 1);
				
				//STEP 2: Build intervalQueue
				Queue<DPVInterval> intervalList = new LinkedList<DPVInterval>();
				
				//get a list of the detection point variables from each expression (avoids duplicates)
				ArrayList<DetectionPointVariable> dpvList = new ArrayList<DetectionPointVariable>();
				for (Expression expression : expressions) {
					
					for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {
						
						if (dpvList.contains(detectionPointVariable) == false) {
							dpvList.add(detectionPointVariable);
						}
					}
				}
				
				for (DetectionPointVariable detectionPointVariable : dpvList) {
					Queue<Event> eventQueue = new LinkedList<Event>();
					
					for (Event event : existingEvents) {
						
						if (DateUtils.fromString(event.getTimestamp()).isBefore(lastExpressionStartTime)) {
							
							//todo: make sure this is the correct function
							//if matches current detection point
							if (event.getDetectionPoint().typeAndThresholdMatches(detectionPointVariable.getDetectionPoint())) {
								
								eventQueue.add(event);
								
								//check if queue is full 
								if (eventQueue.size() >= detectionPointVariable.getDetectionPoint().getThreshold().getCount()) {
									
									//is event interval less that threshold interval
									long queueIntervalInMillis = DateUtils.fromString(event.getTimestamp()).minusMillis(
											(int)DateUtils.fromString(eventQueue.peek().getTimestamp()).getMillis()).getMillis();
									if ( queueIntervalInMillis <= detectionPointVariable.getDetectionPoint().getThreshold().getInterval().toMillis()) {
										//todo: this approximation needs to be fixed, it will cause problems
										intervalList.add(new DPVInterval((int)(queueIntervalInMillis * 1000), "seconds", DateUtils.fromString(event.getTimestamp()), detectionPointVariable));
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
				
				for (Expression expression : expressions) {					
					//filter out intervals from intervalQueue that are occur before the searchStartTime
					DPVInterval peekInterval = intervalList.peek();
					
					while (peekInterval.getStartTime().isBefore(searchStartTime)) {
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
						DateTime possibleExpressionEndTime = possibleExpressionStartTime.plusMillis((int)expression.getInterval().toMillis());

						//int count = 0;
						//boolean isPossibleExpressionTriggered = false;
						
						//create hash map to track which detection point variables had a detection point triggered
						HashMap<DetectionPointVariable, DPVInterval> dpvIntervalMap = new HashMap<DetectionPointVariable, DPVInterval>();
						
						for (DetectionPointVariable detectionPointVariable : expression.getDetectionPointVariables()) {
							dpvIntervalMap.put(detectionPointVariable, null);
						}
						
						for (DPVInterval dpvInterval : expressionIntervalList) {
							
							if (dpvInterval.getEndTime().isBefore(possibleExpressionEndTime)) {

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
						
						if (evaluateExpression(expression, dpvIntervalMap) == true) {
							isExpressionTriggered = true;
							
							//find the latest time in dpv interval mapping
							for (DetectionPointVariable detectionPointVariable : dpvIntervalMap.keySet()) {
								
								if (dpvIntervalMap.get(detectionPointVariable).getEndTime().isAfter(searchStartTime)) {
									searchStartTime = dpvIntervalMap.get(detectionPointVariable).getEndTime();
								}
							}
							
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
					logger.info("Violation Observed for user <" + triggerEvent.getUser().getUsername() + "> - storing attack");
					
					//have determined this event triggers attack
					//ensure appropriate detection point is being used (associated responses, etc.)
					Attack attack = new Attack(
							triggerEvent.getUser(),
							configuredDetectionPoint,
							triggerEvent.getTimestamp(),
							triggerEvent.getDetectionSystem(),
							triggerEvent.getResource()
							);
					
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
	protected DateTime findMostRecentAttackTime(Event event, DetectionPoint configuredDetectionPoint) {
		DateTime newest = DateUtils.epoch();
		
		SearchCriteria criteria = new SearchCriteria().
				setUser(event.getUser()).
				setDetectionPoint(configuredDetectionPoint).
				setDetectionSystemIds(appSensorServer.getConfiguration().getRelatedDetectionSystems(event.getDetectionSystem()));
		
		Collection<Attack> attacks = appSensorServer.getAttackStore().findAttacks(criteria);
		
		for (Attack attack : attacks) {
			if (DateUtils.fromString(attack.getTimestamp()).isAfter(newest)) {
				newest = DateUtils.fromString(attack.getTimestamp());
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
		rules.add(rule);
	}
	
	public void removeRule(Rule rule) {
		rules.remove(rule);
	}
	
	public void clearRules() {
		rules = new ArrayList<Rule>();
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
}
