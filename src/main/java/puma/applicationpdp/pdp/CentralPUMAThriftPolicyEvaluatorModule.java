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

import java.net.URI;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import puma.rest.client.CentralPDPClient;
import puma.rest.domain.AttributeValue;
import puma.rest.domain.DataType;
import puma.rest.domain.Multiplicity;
import puma.rest.domain.ObjectType;
import puma.rest.domain.ResponseType;
import puma.util.timing.TimerFactory;

import com.codahale.metrics.Timer;
import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.PDP;
import com.sun.xacml.attr.BooleanAttribute;
import com.sun.xacml.attr.DateTimeAttribute;
import com.sun.xacml.attr.DoubleAttribute;
import com.sun.xacml.attr.IntegerAttribute;
import com.sun.xacml.attr.StringAttribute;
import com.sun.xacml.ctx.CachedAttribute;
import com.sun.xacml.ctx.Result;
import com.sun.xacml.remote.RemotePolicyEvaluatorModule;

public class CentralPUMAThriftPolicyEvaluatorModule extends
		RemotePolicyEvaluatorModule {

	private static final String CENTRAL_PUMA_PDP_HOST = "puma-central-puma-pdp";

	private static final String CENTRAL_PUMA_PDP_PORT = "8080";

	private CentralPDPClient client = new CentralPDPClient(CENTRAL_PUMA_PDP_HOST + ":" + CENTRAL_PUMA_PDP_PORT, "xacml");


	/**
	 * Our logger
	 */
	private final Logger logger = Logger.getLogger(PDP.class.getName());

	public CentralPUMAThriftPolicyEvaluatorModule() {
		
	}

	/**
	 * We do not support evaluation based on a request, we need an id.
	 * 
	 * @return false
	 */
	@Override
	public boolean isRequestSupported() {
		return false;
	}

	/**
	 * We do support policy evaluation based on id.
	 * 
	 * @return true
	 */
	@Override
	public boolean isIdReferenceSupported() {
		return true;
	}

	/**
	 * Returns whether this module supports the given RemotePolicyReference
	 * PolicyId. This is based on the list of ids provided by the tenant policy
	 * evaluation service.
	 * 
	 * @param id
	 *            The PolicyId attribute value of the RemotePolicyReference
	 *            element.
	 */
	@Override
	public boolean supportsId(URI id) {
		return this.supportsId(id.toString());
	}

	/**
	 * Returns whether this module supports the given RemotePolicyReference
	 * PolicyId. This is based on the list of ids provided by the tenant policy
	 * evaluation service.
	 * 
	 * @param id
	 *            The PolicyId attribute value of the RemotePolicyReference
	 *            element.
	 */
	public boolean supportsId(String id) {
		return id.equals("central-puma-policy"); // MDC: I hope I'm not shooting
													// myself in the foot with
													// this shortcut...
	}

	/**
	 * Not supported by this module.
	 * 
	 * @return new Result(Result.DECISION_NOT_APPLICABLE)
	 */
	@Override
	public Result findAndEvaluate(EvaluationCtx context) {
		return new Result(Result.DECISION_NOT_APPLICABLE);
	}

	/**
	 * Find the policy defined by the id and evaluates it using the context.
	 * 
	 * Returns the decision of the tenant as a XACML result. For now, only takes
	 * into account the decision itself, not any obligations etc!!!
	 */
	@Override
	public Result findAndEvaluate(URI id, EvaluationCtx context) {
		// to be sure, check whether we support the given id
		if (!supportsId(id)) {
			logger.warning("Retrieved an id which was not supported: " + id);
			return new Result(Result.DECISION_NOT_APPLICABLE);
		}


		// 1. build the request
		// NOTE not used: RequestType request = context.getRequest();
		// 2. build the cached attributes
		List<AttributeValue> cachedAttributes = convertCachedAttributes(context
				.getRawCachedAttributes());
		// 3. ask for a response
		ResponseType response;
		Timer.Context timerCtx = TimerFactory.getInstance()
				.getTimer(getClass(), "remotepdp.total").time();
		try {
			response = client.evaluate(cachedAttributes);
		} catch (Exception e) {
			logger.log(
					Level.WARNING,
					"Exception when contacting the remote PUMA PDP => default deny",
					e);
			return new Result(Result.DECISION_DENY);
		} finally {
			timerCtx.stop();
		}
		// 4. process the response
		if (response == ResponseType.DENY) {
			return new Result(Result.DECISION_DENY);
		} else if (response == ResponseType.PERMIT) {
			return new Result(Result.DECISION_PERMIT);
		} else if (response == ResponseType.NOT_APPLICABLE) {
			return new Result(Result.DECISION_NOT_APPLICABLE);
		} else {
			return new Result(Result.DECISION_INDETERMINATE);
		}
	}

	@SuppressWarnings("unchecked")
	private List<AttributeValue> convertCachedAttributes(
			Collection<CachedAttribute> cachedAttributes) {
		// preprocess the input
		List<AttributeValue> values = new LinkedList<AttributeValue>();
		for (CachedAttribute ca : cachedAttributes) {
			String type = ca.getType();
			ObjectType oType = inferObjectType(ca);
			if (type.equals(StringAttribute.identifier)) {
				AttributeValue avp = new AttributeValue(DataType.STRING, oType, Multiplicity.GROUPED,
						ca.getId());
				for (StringAttribute av : (Collection<StringAttribute>) ca
						.getValue().getValue()) {
					avp.addToStringValues(av.getValue());
				}
				values.add(avp);
			} else if (type.equals(IntegerAttribute.identifier)) {
				AttributeValue avp = new AttributeValue(DataType.INTEGER, oType, Multiplicity.GROUPED,
						ca.getId());
				for (IntegerAttribute av : (Collection<IntegerAttribute>) ca
						.getValue().getValue()) {
					avp.addToIntValues((int) av.getValue());
				}
				values.add(avp);
			} else if (type.equals(BooleanAttribute.identifier)) {
				AttributeValue avp = new AttributeValue(DataType.BOOLEAN, oType, Multiplicity.GROUPED,
						ca.getId());
				for (BooleanAttribute av : (Collection<BooleanAttribute>) ca
						.getValue().getValue()) {
					avp.addToBooleanValues(av.getValue());
				}
				values.add(avp);
			} else if (type.equals(DateTimeAttribute.identifier)) {
				AttributeValue avp = new AttributeValue(DataType.DATETIME, oType, Multiplicity.GROUPED,
						ca.getId());
				for (DateTimeAttribute av : (Collection<DateTimeAttribute>) ca
						.getValue().getValue()) {
					// NOTE: we store the time as the long resulting from
					// getTime()
					// This long is the number of milliseconds since 1970.
					// Also note that UNIX time is the number of *seconds* since
					// 1970.
					avp.addToDatetimeValues(av.getValue().getTime());
				}
				values.add(avp);
			} else if (type.equals(DoubleAttribute.identifier)) {
				AttributeValue avp = new AttributeValue(DataType.DOUBLE, oType, Multiplicity.GROUPED, ca.getId());
				for (DoubleAttribute av : (Collection<DoubleAttribute>) ca.getValue().getValue()) {
					avp.addToDoubleValues(av.getValue());
				}
			} else {
				throw new RuntimeException("Unsupport attribute type given: "
						+ type);
			}
		}
		return values;
	}
	
	private ObjectType inferObjectType(CachedAttribute attr) {
		if(attr.getId().contains("subject:"))
			return ObjectType.SUBJECT;
		else if(attr.getId().contains("object:"))
			return ObjectType.RESOURCE;
		else if(attr.getId().contains("resource:"))
			return ObjectType.RESOURCE;
		else if(attr.getId().contains("action:"))
			return ObjectType.ACTION;
		else if(attr.getId().contains("environment:"))
			return ObjectType.ENVIRONMENT;
		else if(attr.getId().contains("env:"))
			return ObjectType.ENVIRONMENT;
		else
			throw new RuntimeException("Cannot infer whether subject/action/object/environment for cached attribute \"" + attr +"\"");
	}

}
