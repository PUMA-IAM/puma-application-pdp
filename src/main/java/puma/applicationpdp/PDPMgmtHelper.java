package puma.applicationpdp;

import java.io.Serializable;
import java.util.Map;
import java.util.Set;

import puma.rmi.pdp.mgmt.ApplicationPDPMgmtRemote;

public interface PDPMgmtHelper extends Serializable {

	ApplicationPDPMgmtRemote getPDPMgmt(String name);
	Map<String, ApplicationPDPMgmtRemote> getAll();
	Set<String> getSupportedNames();
	//String getId();
	//String getStatus();
	
}
