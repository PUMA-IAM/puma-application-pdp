package puma.applicationpdp;

import java.io.InputStream;
import java.security.InvalidParameterException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import oasis.names.tc.xacml._2_0.context.schema.os.ActionType;
import oasis.names.tc.xacml._2_0.context.schema.os.AttributeType;
import oasis.names.tc.xacml._2_0.context.schema.os.AttributeValueType;
import oasis.names.tc.xacml._2_0.context.schema.os.EnvironmentType;
import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;
import oasis.names.tc.xacml._2_0.context.schema.os.ResourceType;
import oasis.names.tc.xacml._2_0.context.schema.os.SubjectType;
import puma.applicationpdp.pdp.MultiPolicyPDP;
import puma.peputils.Action;
import puma.peputils.Environment;
import puma.peputils.Object;
import puma.peputils.PEP;
import puma.peputils.Subject;

import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.attr.StringAttribute;
import com.sun.xacml.ctx.CachedAttribute;
import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.ctx.Result;

/**
 * The main (only) class for accessing the Application PDP from the application. 
 * 
 * NOTICE: the PDP should be initialized using initializePDP(dir)
 *		   before the first call to isAuthorized().
 *
 * NOTICE: the PEP just asks the PDP to evaluate the policy with id "application-policy",
 * 		   so make sure this one is present and know that the rest will not be evaluated.
 * 
 * @author Maarten Decat
 *
 */
public class ApplicationPEP implements PEP {
	
	private static final String APPLICATION_POLICY_ID = "application-policy";

	private static final Logger logger = Logger
			.getLogger(ApplicationPEP.class.getName());
	
	/***********************
	 * SINGLETON STUFF
	 ***********************/
	
	private static ApplicationPEP instance;
	
	public static ApplicationPEP getInstance() {
		if(instance == null) {
			instance = new ApplicationPEP();
		}
		return instance;
	}
	
	/***********************
	 * CONSTRUCTOR
	 ***********************/
	
	private MultiPolicyPDP pdp;
	
	public ApplicationPEP() {
		// NOTICE: the PDP should be initialized using initializePDP(dir)
		// before the first call to isAuthorized()
		this.pdp = null;
	}
	
	/**
	 * Initialize the application PDP with the given list of policy files
	 * (represented by their respective InputStreams).
	 * 
	 * This method should be called before the first call to isAuthorized()
	 * @param policyDir
	 */
	public void initializePDP(Collection<InputStream> policies) {
		this.pdp = new MultiPolicyPDP(policies);
		// check that "application-pdp" is present
		if(!this.pdp.getSupportedPolicyIds().contains(APPLICATION_POLICY_ID)) {
			throw new InvalidParameterException("The application policy was not found (should have id \"" + APPLICATION_POLICY_ID + "\")");
		}
	}
	
	/***********************
	 * GETTING AUTHORIZATION DECISIONS
	 ***********************/
	
	/**
	 * Returns whether the given subject is allows to perform the given action
	 * on the given object.
	 * 
	 * This method is the central method that will invoke all necessary PDPs.
	 * To do this, this PEP will just contact the local Application PDP, which will
	 * try to reach a decision purely from the attributes given when calling this method.
	 * If this is not enough, the local Application PDP will contact the central PUMA PDP,
	 * which has access to more attributes. Similarly, if this PDP cannot reach a decision,
	 * the central PUMA PDP will contact the tenant's PDP.
	 * 
	 * @param subject
	 * @param object
	 * @param action
	 * @return
	 */
	public boolean isAuthorized(Subject subject, Object object, Action action, Environment environment) {
		// build a request containing the ids of the subject, object and action AND put ALL attributes
		// already in the cache
		RequestType asRequest = asRequest(subject, object, action);
		List<CachedAttribute> asCachedAttributes = asCachedAttributes(subject, object, action, environment);
		ResponseCtx response = pdp.evaluate(APPLICATION_POLICY_ID, asRequest, asCachedAttributes);
		
		if(!getStatus(response).equals("ok")) {
			logger.severe("An error occured in the policy evaluation for " + getIds(subject, object, action) + ". Status was: " + getStatus(response));
			return false;
		} else {
			// return true if the decision was Permit, return false in any other case
			int decision = getDecision(response);
			switch (decision) {
			case Result.DECISION_PERMIT:
				logger.info("Authorization decision for " + getIds(subject, object, action) + " was Permit");
				return true;
			case Result.DECISION_INDETERMINATE:
				logger.warning("Authorization decision for " + getIds(subject, object, action) + " was Indeterminate");
				return false;
			case Result.DECISION_NOT_APPLICABLE:
				logger.warning("Authorization decision for " + getIds(subject, object, action) + " was Not Applicable");
				return false;
			case Result.DECISION_DENY:
				logger.info("Authorization decision for " + getIds(subject, object, action) + " was Deny");
				return false;
			default:
				logger.severe("An unknown result was returned by the PDP: " + decision);
				return false;
			}
		}
	}

	/**
	 * Helper function
	 * 
	 * @param subject
	 * @param object
	 * @param action
	 * @return
	 */
	private static String getIds(Subject subject, Object object, Action action) {
		return "(" + subject.getId() + ", " + object.getId() + ", " + action.getId() + ")";
	}
	
	/**
	 * Helper function to retrieve the attributes of the given subject, object, action and
	 * environment as cached attributes.
	 */
	private List<CachedAttribute> asCachedAttributes(Subject subject, Object object, Action action, Environment environment) {
		List<CachedAttribute> result = new LinkedList<CachedAttribute>();
		result.addAll(subject.asCachedAttributes());
		result.addAll(object.asCachedAttributes());
		result.addAll(action.asCachedAttributes());
		result.addAll(environment.asCachedAttributes());
		return result;
	}
	
	/**
	 * Helper function to create a XACML request from a Subject, Object and Action.
	 */
	protected RequestType asRequest(Subject subject, Object object, Action action) {
		SubjectType xacmlSubject = new SubjectType();
		AttributeType subjectId = new AttributeType();
		subjectId.setAttributeId("subject:id");
		subjectId.setDataType(StringAttribute.identifier);
		AttributeValueType subjectIdValue = new AttributeValueType();
		//subjectIdValue.getContent().add(subject.getId());
		subjectIdValue.getContent().add("THE-SUBJECT-ID-IN-THE-REQUEST-WHICH-SHOULD-NEVER-BE-NEEDED");
		subjectId.getAttributeValue().add(subjectIdValue);
		xacmlSubject.getAttribute().add(subjectId);
		
		ResourceType xacmlObject = new ResourceType();
		AttributeType objectId = new AttributeType();
		objectId.setAttributeId(EvaluationCtx.RESOURCE_ID); // this should be the official id apparently
		objectId.setDataType(StringAttribute.identifier);
		AttributeValueType objectIdValue = new AttributeValueType();
		//objectIdValue.getContent().add(object.getId());
		objectIdValue.getContent().add("THE-OBJECT-ID-IN-THE-REQUEST-WHICH-SHOULD-NEVER-BE-NEEDED");
		objectId.getAttributeValue().add(objectIdValue);
		xacmlObject.getAttribute().add(objectId);
		
		ActionType xacmlAction = new ActionType();
		AttributeType actionId = new AttributeType();
		actionId.setAttributeId("action:id");
		actionId.setDataType(StringAttribute.identifier);
		AttributeValueType actionIdValue = new AttributeValueType();
		//actionIdValue.getContent().add(action.getId());
		actionIdValue.getContent().add("THE-ACTION-ID-IN-THE-REQUEST-WHICH-SHOULD-NEVER-BE-NEEDED");
		actionId.getAttributeValue().add(actionIdValue);
		xacmlAction.getAttribute().add(actionId);
		
		EnvironmentType xacmlEnvironment = new EnvironmentType(); // empty in the request
		
		RequestType xacmlRequest = new RequestType();
		xacmlRequest.getSubject().add(xacmlSubject);
		xacmlRequest.getResource().add(xacmlObject);
		xacmlRequest.setAction(xacmlAction);
		xacmlRequest.setEnvironment(xacmlEnvironment);
		
		return xacmlRequest;
	}

	/**
	 * Helper function to get the status from a response context.
	 * Returns "ok" if everything was ok.
	 * 
	 * @param response
	 * @return
	 */
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
			return parts[parts.length-1];
		}
		return null;
	}

	/**
	 * Helper function to get the decision from a response context.
	 * See Result.DECISION_X for the list of possible results.
	 * 
	 * @param response
	 * @return
	 */
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
