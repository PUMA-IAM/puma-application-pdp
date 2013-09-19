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

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.PolicyMetaData;
import com.sun.xacml.VersionConstraints;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.PolicyFinderModule;
import com.sun.xacml.finder.PolicyFinderResult;

public class SimplePolicyFinderModule extends PolicyFinderModule {
	
	private AbstractPolicy policy;
	
	public SimplePolicyFinderModule(AbstractPolicy policy) {
		this.policy = policy;
	}

	@Override
	public void init(PolicyFinder finder) {
		// nothing to do
	}

	@Override
	public PolicyFinderResult findPolicy(EvaluationCtx context) {
		return new PolicyFinderResult(policy);
	}

	@Override
	public PolicyFinderResult findPolicy(URI idReference, int type,
			VersionConstraints constraints, PolicyMetaData parentMetaData) {
		return new PolicyFinderResult(policy);
	}

	@Override
	public boolean isRequestSupported() {
		return true;
	}
	
	

}
