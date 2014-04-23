package puma.applicationpdp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import oasis.names.tc.xacml._2_0.context.schema.os.ActionType;
import oasis.names.tc.xacml._2_0.context.schema.os.AttributeType;
import oasis.names.tc.xacml._2_0.context.schema.os.AttributeValueType;
import oasis.names.tc.xacml._2_0.context.schema.os.EnvironmentType;
import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;
import oasis.names.tc.xacml._2_0.context.schema.os.ResourceType;
import oasis.names.tc.xacml._2_0.context.schema.os.SubjectType;

import org.apache.commons.io.FileUtils;

import puma.applicationpdp.pdp.ApplicationPDP;
import puma.peputils.Action;
import puma.peputils.Environment;
import puma.peputils.Object;
import puma.peputils.PEP;
import puma.peputils.Subject;
import puma.rmi.pdp.mgmt.ApplicationPDPMgmtRemote;
import puma.util.timing.TimerFactory;

import com.codahale.metrics.Timer;
import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.attr.StringAttribute;
import com.sun.xacml.ctx.CachedAttribute;
import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.ctx.Result;

/**
 * The main (only) class for accessing the Application PDP from the application.
 * 
 * NOTICE: the PDP should be initialized using initializePDP(dir) before the
 * first call to isAuthorized().
 * 
 * NOTICE: the PEP just asks the PDP to evaluate the policy with id
 * "application-policy", so make sure this one is present and know that the rest
 * will not be evaluated.
 * 
 * NOTICE: this PEP also implements the ApplicationPDPMgmtRemote interface. I
 * know this is not a PDP, but it still fits cleanly. Actually, this PEP is not
 * a PEP in the strict sense, since there is only one ApplicationPEP instance
 * per application node. However, this PEP is a PEP in the sense that it is the
 * boundary between application code (isAuthorized(subject, object, action,
 * environment)) and the PDP.
 * 
 * @author Maarten Decat
 * 
 */
public class ApplicationPEP implements PEP, ApplicationPDPMgmtRemote {

	private static final String APPLICATION_POLICY_FILENAME = "application-policy.xml";

	private static final Logger logger = Logger.getLogger(ApplicationPEP.class
			.getName());

	/***********************
	 * SINGLETON STUFF
	 ***********************/

	private static ApplicationPEP instance;

	public static ApplicationPEP getInstance() {
		if (instance == null) {
			instance = new ApplicationPEP();
		}
		return instance;
	}

	/***********************
	 * CONSTRUCTOR
	 ***********************/

	private ApplicationPDP pdp;

	private String applicationPolicyFilename;

	private String status;
		
	private static final String PDP_TIMER_NAME = "applicationpdp.evaluate";
	private static final String PEP_TIMER_NAME = "pep.isAuthorized";
	
	private ApplicationPEP() {
		// initialize the timer
		
		
		// NOTICE: the PDP should be initialized using initializePDP(dir)
		// before the first call to isAuthorized()
		this.pdp = null;

		status = "NOT INITIALIZED";
	}

	/**
	 * Initialize the application PDP by scanning all policy files in the given
	 * directory.
	 * 
	 * This method should be called before the first call to isAuthorized().
	 * 
	 * @param policyDir
	 *            WITH trailing slash.
	 */
	public void initializePDP(String policyDir) {
		// store for later usage
		this.applicationPolicyFilename = policyDir
				+ APPLICATION_POLICY_FILENAME;

		InputStream applicationPolicyStream;
		try {
			applicationPolicyStream = new FileInputStream(
					applicationPolicyFilename);
		} catch (FileNotFoundException e) {
			logger.log(Level.SEVERE, "Application policy file not found", e);
			status = "APPLICATION POLICY FILE NOT FOUND";
			return;
		}
		this.pdp = new ApplicationPDP(applicationPolicyStream);
		logger.info("initialized application PDP");
		status = "OK";
	}

	/***********************
	 * GETTING AUTHORIZATION DECISIONS
	 ***********************/

	/**
	 * Returns whether the given subject is allows to perform the given action
	 * on the given object.
	 * 
	 * This method is the central method that will invoke all necessary PDPs. To
	 * do this, this PEP will just contact the local Application PDP, which will
	 * try to reach a decision purely from the attributes given when calling
	 * this method. If this is not enough, the local Application PDP will
	 * contact the central PUMA PDP, which has access to more attributes.
	 * Similarly, if this PDP cannot reach a decision, the central PUMA PDP will
	 * contact the tenant's PDP.
	 * 
	 * @param subject
	 * @param object
	 * @param action
	 * @return
	 */
	public boolean isAuthorized(Subject subject, Object object, Action action,
			Environment environment) {
		Timer.Context timerCtx = TimerFactory.getInstance().getTimer(getClass(), PEP_TIMER_NAME).time();
		boolean result = _isAuthorized(subject, object, action, environment);
		timerCtx.stop();
		return result;
	}
	/**
	 * This is the real isAuthorized(). It is just separate to wrap it 
	 * in timer code.
	 * @param subject
	 * @param object
	 * @param action
	 * @param environment
	 * @return
	 */
	private boolean _isAuthorized(Subject subject, Object object, Action action,
			Environment environment) {
		// build a request containing the ids of the subject, object and action
		// AND put ALL attributes
		// already in the cache
		RequestType asRequest = asRequest(subject, object, action);
		List<CachedAttribute> asCachedAttributes = asCachedAttributes(subject,
				object, action, environment);
		Timer.Context timerCtx = TimerFactory.getInstance().getTimer(getClass(), PDP_TIMER_NAME).time();
		ResponseCtx response = pdp.evaluate(asRequest, asCachedAttributes);
		timerCtx.stop();

		if (!getStatus(response).equals("ok")) {
			logger.severe("An error occured in the policy evaluation for "
					+ getIds(subject, object, action) + ". Status was: "
					+ getStatus(response));
			return false;
		} else {
			// return true if the decision was Permit, return false in any other
			// case
			int decision = getDecision(response);
			switch (decision) {
			case Result.DECISION_PERMIT:
				logger.info("Authorization decision for "
						+ getIds(subject, object, action) + " was Permit");
				return true;
			case Result.DECISION_INDETERMINATE:
				logger.warning("Authorization decision for "
						+ getIds(subject, object, action)
						+ " was Indeterminate");
				return false;
			case Result.DECISION_NOT_APPLICABLE:
				logger.warning("Authorization decision for "
						+ getIds(subject, object, action)
						+ " was Not Applicable");
				return false;
			case Result.DECISION_DENY:
				logger.info("Authorization decision for "
						+ getIds(subject, object, action) + " was Deny");
				return false;
			default:
				logger.severe("An unknown result was returned by the PDP: "
						+ decision);
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
		return "(" + subject.getId() + ", " + object.getId() + ", "
				+ action.getId() + ")";
	}

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
	private static int getDecision(ResponseCtx response) {
		Set<Result> results = response.getResults();
		Result result = null;
		for (Result r : results) {
			// the first one if there only is one
			result = r;
		}
		return result.getDecision();
	}

	/***********************
	 * APPLICATION PDP MGMT
	 ***********************/

	@Override
	public String getStatus() {
		return status;
	}

	@Override
	public void loadApplicationPolicy(String policy) {
		PrintWriter writer;
		try {
			writer = new PrintWriter(applicationPolicyFilename, "UTF-8");
		} catch (FileNotFoundException e) {
			logger.log(
					Level.SEVERE,
					"Application policy file not found when writing new application policy",
					e);
			return;
		} catch (UnsupportedEncodingException e) {
			logger.log(Level.SEVERE,
					"Unsupported encoding when writing new application policy",
					e);
			return;
		}
		writer.print(policy);
		writer.close();
		logger.info("Succesfully reloaded application policy");
		this.reload();
	}

	@Override
	public void reload() {
		// just set up a new PDP
		InputStream applicationPolicyStream;
		try {
			applicationPolicyStream = new FileInputStream(
					applicationPolicyFilename);
		} catch (FileNotFoundException e) {
			logger.log(Level.SEVERE,
					"Could not reload PDP: application policy file not found",
					e);
			status = "APPLICATION POLICY FILE NOT FOUND";
			return;
		}
		this.pdp = new ApplicationPDP(applicationPolicyStream);
		logger.info("Reloaded application PDP");
		status = "OK";
	}

	@Override
	public String getApplicationPolicy() {
		try {
			String str = FileUtils.readFileToString(new File(applicationPolicyFilename));
			return str;
		} catch (IOException e) {
			logger.log(Level.WARNING, "IOException when reading application policy file", e);
			return "IOException";
		}
	}

	@Override
	public String getId() throws RemoteException {
		return "" + this.hashCode();
	}
}
