/*******************************************************************************
 * Copyright 2014 KU Leuven Research and Developement - iMinds - Distrinet 
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *    
 *    Administrative Contact: dnet-project-office@cs.kuleuven.be
 *    Technical Contact: maarten.decat@cs.kuleuven.be
 *    Author: maarten.decat@cs.kuleuven.be
 ******************************************************************************/
package puma.applicationpdp.pdp;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import mdc.xacml.impl.DefaultAttributeCounter;
import mdc.xacml.impl.HardcodedEnvironmentAttributeModule;
import mdc.xacml.impl.SimplePolicyFinderModule;
import oasis.names.tc.xacml._2_0.context.schema.os.ActionType;
import oasis.names.tc.xacml._2_0.context.schema.os.AttributeType;
import oasis.names.tc.xacml._2_0.context.schema.os.AttributeValueType;
import oasis.names.tc.xacml._2_0.context.schema.os.EnvironmentType;
import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;
import oasis.names.tc.xacml._2_0.context.schema.os.ResourceType;
import oasis.names.tc.xacml._2_0.context.schema.os.SubjectType;
import puma.peputils.Action;
import puma.peputils.Environment;
import puma.peputils.Object;
import puma.peputils.PDP;
import puma.peputils.PDPDecision;
import puma.peputils.PDPResult;
import puma.peputils.Subject;
import puma.piputils.EntityDatabase;
import puma.piputils.QueryAttributeFinderModule;

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.BasicEvaluationCtx;
import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.PDPConfig;
import com.sun.xacml.ParsingException;
import com.sun.xacml.attr.StringAttribute;
import com.sun.xacml.ctx.CachedAttribute;
import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.ctx.Result;
import com.sun.xacml.finder.AttributeFinder;
import com.sun.xacml.finder.AttributeFinderModule;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.PolicyFinderModule;
import com.sun.xacml.remote.RemotePolicyEvaluator;
import com.sun.xacml.remote.RemotePolicyEvaluatorModule;
import com.sun.xacml.support.finder.PolicyReader;

/**
 * Class used for evaluating one of multiple policies, based on their id.
 * Internally, this PDP builds multiple SimplePDPs.
 * 
 * @author Maarten Decat
 * 
 */
public class ApplicationPDP implements PDP {

	public static final String APPLICATION_POLICY_ID = "application-policy";

	private static final Logger logger = Logger.getLogger(ApplicationPDP.class
			.getName());

	private com.sun.xacml.PDP pdp;

	/**
	 * Initialize this MultiPolicyPDP with given collection of input streams
	 * pointing to XACML policies (XML files).
	 */
	public ApplicationPDP(InputStream applicationPolicyStream,
			Boolean allowRemoteAccess) {
		// Now setup the attribute finder
		// 1. current date/time
		HardcodedEnvironmentAttributeModule envAttributeModule = new HardcodedEnvironmentAttributeModule();
		// 2. selector module for access to request
		// SelectorModule selectorAttributeModule = new SelectorModule();
		// 3. our own attribute finder module
		// LocalAttributeFinderModule localAttributeFinderModule = new
		// LocalAttributeFinderModule();
		// 5. Put everything in an attribute finder
		AttributeFinder attributeFinder = new AttributeFinder();
		List<AttributeFinderModule> attributeModules = new ArrayList<AttributeFinderModule>();
		attributeModules.add(envAttributeModule);
		if (allowRemoteAccess) {
			logger.info("Adding query attribute finder...");
			attributeModules.add(new QueryAttributeFinderModule());
		}
		// attributeModules.add(selectorAttributeModule);
		// attributeModules.add(localAttributeFinderModule);
		attributeFinder.setModules(attributeModules);

		// Also set up the remote policy evaluator
		RemotePolicyEvaluator remotePolicyEvaluator = new RemotePolicyEvaluator();
		Set<RemotePolicyEvaluatorModule> remotePolicyEvaluatorModules = new HashSet<RemotePolicyEvaluatorModule>();
//		remotePolicyEvaluatorModules
//				.add(new CentralPUMAPolicyEvaluatorModule());
		remotePolicyEvaluatorModules
				.add(new CentralPUMAThriftPolicyEvaluatorModule());
		remotePolicyEvaluator.setModules(remotePolicyEvaluatorModules);

		// build the PDP
		PolicyReader reader = new PolicyReader(null);
		AbstractPolicy policy;
		try {
			policy = reader.readPolicy(applicationPolicyStream);
		} catch (ParsingException e) {
			logger.log(Level.SEVERE, "Error when parsing application policy", e);
			return;
		}
		if (!policy.getId().toString().equals(APPLICATION_POLICY_ID)) {
			logger.severe("The id of the given policy should be \""
					+ APPLICATION_POLICY_ID + "\". Given id: \""
					+ policy.getId().toString() + "\".");
			return;
		}

		// construct the policy finder for the single policy
		PolicyFinder policyFinder = new PolicyFinder();
		SimplePolicyFinderModule simplePolicyFinderModule = new SimplePolicyFinderModule(
				policy);
		Set<PolicyFinderModule> policyModules = new HashSet<PolicyFinderModule>();
		policyModules.add(simplePolicyFinderModule);
		policyFinder.setModules(policyModules);
		this.pdp = new com.sun.xacml.PDP(new PDPConfig(attributeFinder, policyFinder, null,
				remotePolicyEvaluator, new DefaultAttributeCounter()));
		EntityDatabase.getInstance().open(true);
	}

	/**
	 * Returns the list of supported policy ids.
	 */
	public List<String> getSupportedPolicyIds() {
		List<String> result = new ArrayList<String>();
		result.add(APPLICATION_POLICY_ID);
		return result;
	}

	/*
	 * Evaluate a request and return the result.
	 *
	private ResponseCtx evaluate(RequestType request) {
		return evaluate(request, new LinkedList<CachedAttribute>());
	}*/

	/**
	 * Evaluate a request and return the result.
	 */
	private ResponseCtx evaluate(RequestType request,
			List<CachedAttribute> cachedAttributes) {
		// Only setup log item if supported,
		// else noop
		if (logAll()) {
			String log = "Received policy request for Application-level PDP. Cached attributes:\n";
			for (CachedAttribute a : cachedAttributes) {
				log += a.getId() + " = " + a.getValue().toString() + "\n";
			}
			logger.info(log);
		}

		// if supported, evaluate the appropriate policy
		BasicEvaluationCtx ctx;
		try {
			ctx = new BasicEvaluationCtx(request,
					this.pdp.getAttributeFinder(),
					this.pdp.getRemotePolicyEvaluator(),
					new DefaultAttributeCounter());
		} catch (ParsingException e) {
			logger.log(Level.SEVERE, "Parsing exception here??", e);
			return null;
		}
		// add the given cached attributes
		ctx.addAttributesToCache(cachedAttributes);
		// evaluate
		ResponseCtx response = this.pdp.evaluate(ctx);
		return response;
	}

	private static Boolean logAll() {
		if (LogManager.getLogManager().getLogger("") == null)
			return false;
		if (LogManager.getLogManager().getLogger("").getLevel() == null)
			return false;
		return !LogManager.getLogManager().getLogger("").getLevel()
				.equals(Level.WARNING);
	}
	
	public PDPResult evaluate(Subject subject, Object object, Action action, Environment environment) {
		RequestType asRequest = asRequest(subject, object, action);
		List<CachedAttribute> asCachedAttributes = asCachedAttributes(subject, object, action, environment);
		
		ResponseCtx response = evaluate(asRequest, asCachedAttributes);
		int decisionInt = getDecision(response);
		
		PDPDecision decision;
		switch (decisionInt) {
		case Result.DECISION_PERMIT:
			decision = PDPDecision.PERMIT;
			break;
		case Result.DECISION_INDETERMINATE:
			decision = PDPDecision.INDETERMINATE;
			break;
		case Result.DECISION_NOT_APPLICABLE:
			decision = PDPDecision.NOT_APPLICABLE;
			break;
		case Result.DECISION_DENY:
			decision = PDPDecision.DENY;
			break;
		default:
			decision = PDPDecision.UNKNOWN;
			break;
		}
		
		return new PDPResult(decision, getStatus(response));
	}
	
	
	
	/**************************************************************
	 ******************* HELPER FUNCTIONS *************************
	 **************************************************************/
	
	
	
	/**
	 * Helper function to retrieve the attributes of the given subject, object,
	 * action and environment as cached attributes.
	 */
	private List<CachedAttribute> asCachedAttributes(Subject subject,
			Object object, Action action, Environment environment) {
		List<CachedAttribute> result = new LinkedList<CachedAttribute>();
		result.addAll(subject.asCachedAttributes());
		result.addAll(object.asCachedAttributes());
		result.addAll(action.asCachedAttributes());
		result.addAll(environment.asCachedAttributes());
		return result;
	}

	/**
	 * Helper function to create a XACML request from a Subject, Object and
	 * Action.
	 */
	protected RequestType asRequest(Subject subject, Object object,
			Action action) {
		SubjectType xacmlSubject = new SubjectType();
		AttributeType subjectId = new AttributeType();
		subjectId.setAttributeId("subject:id-which-should-never-be-needed");
		subjectId.setDataType(StringAttribute.identifier);
		AttributeValueType subjectIdValue = new AttributeValueType();
		// subjectIdValue.getContent().add(subject.getId());
		subjectIdValue.getContent().add(
				"THE-SUBJECT-ID-IN-THE-REQUEST-WHICH-SHOULD-NEVER-BE-NEEDED");
		subjectId.getAttributeValue().add(subjectIdValue);
		xacmlSubject.getAttribute().add(subjectId);

		ResourceType xacmlObject = new ResourceType();
		AttributeType objectId = new AttributeType();
		objectId.setAttributeId(EvaluationCtx.RESOURCE_ID); // this should be
															// the official id
															// apparently
		objectId.setDataType(StringAttribute.identifier);
		AttributeValueType objectIdValue = new AttributeValueType();
		// objectIdValue.getContent().add(object.getId());
		objectIdValue.getContent().add(
				"THE-OBJECT-ID-IN-THE-REQUEST-WHICH-SHOULD-NEVER-BE-NEEDED");
		objectId.getAttributeValue().add(objectIdValue);
		xacmlObject.getAttribute().add(objectId);

		ActionType xacmlAction = new ActionType();
		AttributeType actionId = new AttributeType();
		actionId.setAttributeId("action:id-which-should-never-be-needed");
		actionId.setDataType(StringAttribute.identifier);
		AttributeValueType actionIdValue = new AttributeValueType();
		// actionIdValue.getContent().add(action.getId());
		actionIdValue.getContent().add(
				"THE-ACTION-ID-IN-THE-REQUEST-WHICH-SHOULD-NEVER-BE-NEEDED");
		actionId.getAttributeValue().add(actionIdValue);
		xacmlAction.getAttribute().add(actionId);

		EnvironmentType xacmlEnvironment = new EnvironmentType(); // empty in
																	// the
																	// request

		RequestType xacmlRequest = new RequestType();
		xacmlRequest.getSubject().add(xacmlSubject);
		xacmlRequest.getResource().add(xacmlObject);
		xacmlRequest.setAction(xacmlAction);
		xacmlRequest.setEnvironment(xacmlEnvironment);

		return xacmlRequest;
	}

	/**
	 * Helper function to get the status from a response context. Returns "ok"
	 * if everything was ok.
	 * 
	 * @param response
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private static String getStatus(ResponseCtx response) {
		Set<Result> results = response.getResults();
		Result result = null;
		for (Result r : results) {
			// the first one if there only is one
			result = r;
		}
		List<String> stati = result.getStatus().getCode();
		for (String status : stati) {
			String[] parts = status.split(":");
			return parts[parts.length - 1];
		}
		return null;
	}

	/**
	 * Helper function to get the decision from a response context. See
	 * Result.DECISION_X for the list of possible results.
	 * 
	 * @param response
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private static int getDecision(ResponseCtx response) {
		Set<Result> results = response.getResults();
		Result result = null;
		for (Result r : results) {
			// the first one if there only is one
			result = r;
		}
		return result.getDecision();
	}
}
