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

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.attr.AttributeDesignator;
import com.sun.xacml.attr.AttributeValue;
import com.sun.xacml.attr.BagAttribute;
import com.sun.xacml.attr.DateTimeAttribute;
import com.sun.xacml.cond.EvaluationResult;
import com.sun.xacml.ctx.Status;
import com.sun.xacml.finder.AttributeFinderModule;

/**
 * Supports hard-coded values for current date, time, and dateTime values. 
 * 
 * @author Maarten Decat
 */
public class HardcodedEnvironmentAttributeModule extends AttributeFinderModule {

	/**
	 * Standard environment variable that represents the current date and time
	 */
	public static final String ENVIRONMENT_CURRENT_DATETIME = "environment:currentDateTime";

	/**
	 * Returns true always because this module supports designators.
	 * 
	 * @return true always
	 */
	public boolean isDesignatorSupported() {
		return true;
	}

	/**
	 * Returns a <code>Set</code> with a single <code>Integer</code> specifying
	 * that environment attributes are supported by this module.
	 * 
	 * @return a <code>Set</code> with
	 *         <code>AttributeDesignator.ENVIRONMENT_TARGET</code> included
	 */
	public Set getSupportedDesignatorTypes() {
		HashSet set = new HashSet();
		set.add(new Integer(AttributeDesignator.ENVIRONMENT_TARGET));
		return set;
	}

	/**
     * 
     */
	public EvaluationResult findAttribute(URI attributeType, URI attributeId,
			URI issuer, URI subjectCategory, EvaluationCtx context,
			int designatorType) {
		// we only know about environment attributes
		if (designatorType != AttributeDesignator.ENVIRONMENT_TARGET) {
			return new EvaluationResult(
					BagAttribute.createEmptyBag(attributeType));
		}

		// figure out which attribute we're looking for
		String attrName = attributeId.toString();

		if (attrName.equals(ENVIRONMENT_CURRENT_DATETIME)) {
			// make sure they're asking for a dateTime attribute
			if (!attributeType.toString().equals(DateTimeAttribute.identifier)) {
				return new EvaluationResult(
						BagAttribute.createEmptyBag(attributeType));
			}

			// get the value from the context
			// use the date helper in order to receive a hardcoded value in the tests
			DateHelper d = new DateHelper();
			List<AttributeValue> result = new ArrayList<AttributeValue>();
			result.add(new DateTimeAttribute(d.now()));
			return new EvaluationResult(new BagAttribute(attributeType, result));
		}

		// if we got here, then it's an attribute that we don't know
		return new EvaluationResult(BagAttribute.createEmptyBag(attributeType));
	}

	/**
	 * Private helper that generates a new processing error status and includes
	 * the given string.
	 */
	private EvaluationResult makeProcessingError(String message) {
		ArrayList code = new ArrayList();
		code.add(Status.STATUS_PROCESSING_ERROR);
		return new EvaluationResult(new Status(code, message));
	}

	/**
	 * Private helper that makes a bag containing only the given attribute.
	 */
	private EvaluationResult makeBag(AttributeValue attribute) {
		Set set = new HashSet();
		set.add(attribute);

		BagAttribute bag = new BagAttribute(attribute.getType(), set);

		return new EvaluationResult(bag);
	}

}
