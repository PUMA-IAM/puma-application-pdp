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
package puma.applicationpdp;

import java.util.logging.Logger;

import puma.peputils.Action;
import puma.peputils.Environment;
import puma.peputils.Subject;
import puma.peputils.attributes.EnvironmentAttributeValue;
import puma.peputils.attributes.Multiplicity;
import puma.peputils.attributes.ObjectAttributeValue;
import puma.peputils.attributes.SubjectAttributeValue;
import puma.util.timing.TimerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

public class Example {
	
	private static final Logger logger = Logger
			.getLogger(Example.class.getName());

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// 0. Initialize the PDP
		ApplicationPEP.getInstance().initializePDP("/home/maartend/PhD/code/workspace-jee/puma-application-pdp/resources/policies/");
		
		// 1. First build your subject, object, action and environment, for example
		// based on the current Session or some parameters in the request
		Subject subject = new Subject("maarten");
		SubjectAttributeValue roles = new SubjectAttributeValue("roles", Multiplicity.GROUPED);
		roles.addValue("helpdesk");
		roles.addValue("iminds-pr");
		roles.addValue("boss-of-Jasper");
		subject.addAttributeValue(roles);
		subject.addAttributeValue(new SubjectAttributeValue("departement", Multiplicity.ATOMIC, "computer-science"));
		subject.addAttributeValue(new SubjectAttributeValue("fired", Multiplicity.ATOMIC, false));
		subject.addAttributeValue(new SubjectAttributeValue("tenant", Multiplicity.GROUPED, "1"));
		subject.addAttributeValue(new SubjectAttributeValue("email", Multiplicity.ATOMIC, "maarten.decat@cs.kuleuven.be"));
		subject.addAttributeValue(new SubjectAttributeValue("ancienity", Multiplicity.ATOMIC, 7));
		
		puma.peputils.Object object = new puma.peputils.Object("123"); // damn, Object moet blijkbaar niet geïmporteerd worden...
		object.addAttributeValue(new ObjectAttributeValue("type", Multiplicity.ATOMIC, "document"));
		object.addAttributeValue(new ObjectAttributeValue("creating-tenant", Multiplicity.ATOMIC, "2"));
		object.addAttributeValue(new ObjectAttributeValue("owning-tenant", Multiplicity.ATOMIC, "TODO"));
		object.addAttributeValue(new ObjectAttributeValue("location", Multiplicity.ATOMIC, "/docs/stuff/blabla/123.pdf"));
		object.addAttributeValue(new ObjectAttributeValue("sender", Multiplicity.ATOMIC, "bert"));
		ObjectAttributeValue destinations = new ObjectAttributeValue("destinations", Multiplicity.GROUPED);
		destinations.addValue("lantam@cs.kuleuven.be");
		destinations.addValue("iemand@example.com");
		
		Action action = new Action("delete");
		
		Environment environment = new Environment();
		environment.addAttributeValue(new EnvironmentAttributeValue("system-status", Multiplicity.ATOMIC, "overload"));
		environment.addAttributeValue(new EnvironmentAttributeValue("system-load", Multiplicity.ATOMIC, 90));
		
		// 2. Then just ask the PEP for a decision
		boolean authorized = ApplicationPEP.getInstance().isAuthorized(subject, object, action, environment);
		
		// 3. Enforce the decision
		if(!authorized) {
			System.out.println("You shall not pass.");
		} else {
			System.out.println("You are authorized, here you can see the contents of document #123");
		}
		
		try {
			ObjectMapper mapper = new ObjectMapper();
			ObjectWriter writer = mapper.writerWithDefaultPrettyPrinter();
			String metrics = writer.writeValueAsString(TimerFactory.getInstance().getMetricRegistry());
			System.out.println("metrics: " + metrics);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}

	}

}
