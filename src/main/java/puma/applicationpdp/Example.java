package puma.applicationpdp;

import java.util.logging.Logger;

import puma.peputils.Action;
import puma.peputils.Environment;
import puma.peputils.Subject;
import puma.peputils.attributes.EnvironmentAttributeValue;
import puma.peputils.attributes.ObjectAttributeValue;
import puma.peputils.attributes.SubjectAttributeValue;

public class Example {
	
	private static final Logger logger = Logger
			.getLogger(Example.class.getName());

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// 0. Initialize the PDP
		ApplicationPEP.getInstance().initializePDP("/home/jasper/git/puma-application-pdp/src/main/resources/policies/");
		
		// 1. First build your subject, object, action and environment, for example
		// based on the current Session or some parameters in the request
		Subject subject = new Subject("maarten");
		SubjectAttributeValue roles = new SubjectAttributeValue("roles");
		roles.addValue("phd");
		roles.addValue("iminds-pr");
		roles.addValue("boss-of-Jasper");
		subject.addAttributeValue(roles);
		subject.addAttributeValue(new SubjectAttributeValue("departement", "computer-science"));
		subject.addAttributeValue(new SubjectAttributeValue("fired", false));
		subject.addAttributeValue(new SubjectAttributeValue("tenant", "KUL"));
		subject.addAttributeValue(new SubjectAttributeValue("email", "maarten.decat@cs.kuleuven.be"));
		
		puma.peputils.Object object = new puma.peputils.Object("123"); // damn, Object moet blijkbaar niet geïmporteerd worden...
		object.addAttributeValue(new ObjectAttributeValue("type", "document"));
		object.addAttributeValue(new ObjectAttributeValue("owning-tenant", "IMEC"));
		object.addAttributeValue(new ObjectAttributeValue("location", "/docs/stuff/blabla/123.pdf"));
		object.addAttributeValue(new ObjectAttributeValue("sender", "bert"));
		ObjectAttributeValue destinations = new ObjectAttributeValue("destinations");
		destinations.addValue("lantam@cs.kuleuven.be");
		destinations.addValue("iemand@example.com");
		
		Action action = new Action("read");
		
		Environment environment = new Environment();
		environment.addAttributeValue(new EnvironmentAttributeValue("system-status", "overload"));
		environment.addAttributeValue(new EnvironmentAttributeValue("system-load", 90));
		
		// 2. Then just ask the PEP for a decision
		boolean authorized = ApplicationPEP.getInstance().isAuthorized(subject, object, action, environment);
		
		// 3. Enforce the decision
		if(!authorized) {
			System.out.println("You shall not pass.");
			return;
		}
		
		System.out.println("You are authorized, here you can see the contents of document #123");

	}

}
