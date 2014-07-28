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

import org.apache.thrift.TException;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;

import puma.thrift.pdp.AttributeValueP;
import puma.thrift.pdp.DataTypeP;
import puma.thrift.pdp.RemotePDPService;
import puma.thrift.pdp.ResponseTypeP;
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

	private static final int CENTRAL_PUMA_PDP_THRIFT_PORT = 9091;

	RemotePDPService.Client client;

	TTransport transport;

	/**
	 * Our logger
	 */
	private final Logger logger = Logger.getLogger(PDP.class.getName());

	public CentralPUMAThriftPolicyEvaluatorModule() {
		setupCentralPUMAPDPConnection();
	}

	/**
	 * Idempotent helper function to set up the RMI connection to the central
	 * PUMA PDP.
	 */
	private void setupCentralPUMAPDPConnection() {
		if (!isCentralPUMAPDPConnectionOK()) {
			// set up Thrift
			transport = new TSocket(CENTRAL_PUMA_PDP_HOST,
					CENTRAL_PUMA_PDP_THRIFT_PORT);
			try {
				transport.open();
			} catch (TTransportException e) {
				logger.log(Level.WARNING,
						"FAILED to reach the central PUMA PDP", e);
				e.printStackTrace();
			}

			TProtocol protocol = new TBinaryProtocol(transport);
			client = new RemotePDPService.Client(protocol);
			logger.info("Set up Thrift client to Central PUMA PDP");
		}
	}

	/**
	 * Helper function that returns whether the RMI connection to the central
	 * PUMA PDP is set up or not.
	 */
	private boolean isCentralPUMAPDPConnectionOK() {
		return client != null;
	}

	/**
	 * Resets the central PUMA connection so that isCentralPUMAPDPConnectionOK()
	 * returns false and the connection can be set up again using
	 * setupCentralPUMAPDPConnection().
	 */
	private void resetCentralPUMAPDPConnection() {
		transport.close();
		client = null;
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

		// try to set up the RMI connection every time (idempotent!)
		setupCentralPUMAPDPConnection();
		if (!isCentralPUMAPDPConnectionOK()) {
			logger.log(Level.SEVERE,
					"The RMI connection to the remote PUMA PDP was not set up => default deny");
			return new Result(Result.DECISION_DENY);
		}

		// 1. build the request
		// NOTE not used: RequestType request = context.getRequest();
		// 2. build the cached attributes
		List<AttributeValueP> cachedAttributes = convertCachedAttributes(context
				.getRawCachedAttributes());
		// 3. ask for a response
		ResponseTypeP response;
		Timer.Context timerCtx = TimerFactory.getInstance()
				.getTimer(getClass(), "remotepdp.total").time();
		try {
			response = client.evaluateP(cachedAttributes);
		} catch (TException e) {
			logger.log(
					Level.WARNING,
					"TException when contacting the remote PUMA PDP, trying to set up connection again",
					e);
			resetCentralPUMAPDPConnection();
			setupCentralPUMAPDPConnection();
			// try again
			try {
				response = client.evaluateP(cachedAttributes);
			} catch (TException e1) {
				logger.log(
						Level.WARNING,
						"Again TException when contacting the remote PUMA PDP => default deny",
						e);
				return new Result(Result.DECISION_DENY);
			}
		} finally {
			timerCtx.stop();
		}
		// 4. process the response
		if (response == ResponseTypeP.DENY) {
			return new Result(Result.DECISION_DENY);
		} else if (response == ResponseTypeP.PERMIT) {
			return new Result(Result.DECISION_PERMIT);
		} else if (response == ResponseTypeP.NOT_APPLICABLE) {
			return new Result(Result.DECISION_NOT_APPLICABLE);
		} else {
			return new Result(Result.DECISION_INDETERMINATE);
		}
	}

	@SuppressWarnings("unchecked")
	private List<AttributeValueP> convertCachedAttributes(
			Collection<CachedAttribute> cachedAttributes) {
		// preprocess the input
		List<AttributeValueP> values = new LinkedList<AttributeValueP>();
		for (CachedAttribute ca : cachedAttributes) {
			String type = ca.getType();
			if (type.equals(StringAttribute.identifier)) {
				AttributeValueP avp = new AttributeValueP(DataTypeP.STRING,
						ca.getId());
				for (StringAttribute av : (Collection<StringAttribute>) ca
						.getValue().getValue()) {
					avp.addToStringValues(av.getValue());
				}
				values.add(avp);
			} else if (type.equals(IntegerAttribute.identifier)) {
				AttributeValueP avp = new AttributeValueP(DataTypeP.INTEGER,
						ca.getId());
				for (IntegerAttribute av : (Collection<IntegerAttribute>) ca
						.getValue().getValue()) {
					avp.addToIntValues((int) av.getValue());
				}
				values.add(avp);
			} else if (type.equals(BooleanAttribute.identifier)) {
				AttributeValueP avp = new AttributeValueP(DataTypeP.BOOLEAN,
						ca.getId());
				for (BooleanAttribute av : (Collection<BooleanAttribute>) ca
						.getValue().getValue()) {
					avp.addToBooleanValues(av.getValue());
				}
				values.add(avp);
			} else if (type.equals(DateTimeAttribute.identifier)) {
				AttributeValueP avp = new AttributeValueP(DataTypeP.DATETIME,
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
				AttributeValueP avp = new AttributeValueP(DataTypeP.DOUBLE, ca.getId());
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

}
