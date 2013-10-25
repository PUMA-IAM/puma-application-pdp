/*******************************************************************************
 * Copyright 2013 KU Leuven Research and Developement - IBBT - Distrinet 
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

import java.io.StringWriter;
import java.net.URI;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;

import org.w3c.dom.Node;

import puma.centralpdp.rmi.CentralPUMAPDPRemote;

import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.PDP;
import com.sun.xacml.ctx.CachedAttribute;
import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.ctx.Result;
import com.sun.xacml.remote.RemotePolicyEvaluatorModule;

public class CentralPUMAPolicyEvaluatorModule extends RemotePolicyEvaluatorModule {

	/**
	 * Our logger
	 */
	private final Logger logger = Logger.getLogger(PDP.class.getName());
	
	private CentralPUMAPDPRemote centralPUMAPDP;

	public CentralPUMAPolicyEvaluatorModule() {
		try {
			Registry registry = LocateRegistry.getRegistry("central-puma-pdp", 2020);
			centralPUMAPDP = (CentralPUMAPDPRemote) registry.lookup("central-puma-pdp");
		} catch(Exception e) {
			System.err.println("FAILED to reach the central PUMA PDP");
			e.printStackTrace();
		}
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
		return id.equals("central-puma-policy"); // MDC: I hope I'm not shooting myself in the foot with this shortcut...
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
		RequestType request = context.getRequest();
		// 2. build the cached attributes
		List<CachedAttribute> cachedAttributes = new LinkedList<CachedAttribute>();
		cachedAttributes.addAll(context.getRawCachedAttributes());
		// 3. ask for a response
		ResponseCtx response;
		try {
			response = centralPUMAPDP.evaluate(request, cachedAttributes);
		} catch (RemoteException e) {
			System.err.println("RemoteException when contacting the remote PUMA PDP => default deny");
			e.printStackTrace();
			return new Result(Result.DECISION_DENY);
		}
		// 4. process the response
		if(response.getResults().size() == 0) {
			System.err.println("The central PUMA PDP did not return a result?? => default deny");
			return new Result(Result.DECISION_DENY);
		} else if(response.getResults().size() > 1) {
			System.err.println("The central PUMA PDP returned two results?? => default deny");
			return new Result(Result.DECISION_DENY);
		} else {
			for(Object result: response.getResults()) {
				// return the first one
				return (Result) result;
			}
			// will never 
			return null;
		}
	}

	/**
	 * 
	 * @param node
	 * @return
	 */
	private static String nodeToString(Node node) {
		StringWriter sw = new StringWriter();
		try {
			Transformer t = TransformerFactory.newInstance().newTransformer();
			t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			t.setOutputProperty(OutputKeys.INDENT, "yes");
			t.transform(new DOMSource(node), new StreamResult(sw));
		} catch (TransformerException te) {
			te.printStackTrace();
		}
		return sw.toString();
	}

}