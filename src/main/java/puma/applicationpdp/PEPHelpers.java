package puma.applicationpdp;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import puma.peputils.PEP;
import puma.rmi.pdp.mgmt.ApplicationPDPMgmtRemote;
import puma.stapl.pdp.StaplPDP;

public class PEPHelpers implements PEPHelper {
	
	private ApplicationPEP xacmlPEP;
	private StaplPDP staplPEP;
	
	private static PEPHelpers instance;
	private static PDPMgmtHelper mgmtInstance;
	
	private PEPHelpers(ApplicationPEP xacml, StaplPDP stapl) {
		this.xacmlPEP = xacml;
		this.staplPEP = stapl;
	}
	
	public static void init(ApplicationPEP xacml, StaplPDP stapl) {
		if(isInitialized())
			throw new IllegalStateException("PEPHelpers is already initialized.");
		else {
			instance = new PEPHelpers(xacml, stapl);
			mgmtInstance = new PDPMgmtHelperImpl(xacml, stapl);
		}
	}
	
	public static boolean isInitialized() {
		return instance != null;
	}
	
	public static PDPMgmtHelper getPDPMgmtHelper() {
		if(isInitialized())
			return mgmtInstance;
		else
			throw new IllegalStateException("PEPHelpers is not yet initialized.");
	}
	
	public static PEPHelper getPEPHelper() {
		if(isInitialized())
			return instance;
		else
			throw new IllegalStateException("PEPHelpers is not yet initialized.");
	}
	
	@Override
	public PEP getPEP(String name) {
		if("STAPL".equals(name))
			return staplPEP;
		else if("XACML".equals(name))
			return xacmlPEP;
		else throw new IllegalArgumentException("Unknown name: " + name);
	}
	
	@Override
	public boolean equals(Object o) {
		if(o == null)
			return false;
		if(!(o instanceof PEPHelpers))
			return false;
		final PEPHelpers that = (PEPHelpers) o;
		return this.staplPEP == that.staplPEP && this.xacmlPEP == that.xacmlPEP;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((staplPEP == null) ? 0 : staplPEP.hashCode());
		result = prime * result + ((xacmlPEP == null) ? 0 : xacmlPEP.hashCode());
		return result;
	}

	
	private static class PDPMgmtHelperImpl implements PDPMgmtHelper {

		private static final long serialVersionUID = 1L;
		
		private ApplicationPDPMgmtRemote xacmlPEP;
		private ApplicationPDPMgmtRemote staplPEP;
		
		PDPMgmtHelperImpl(ApplicationPDPMgmtRemote xacml, ApplicationPDPMgmtRemote stapl) {
			this.xacmlPEP = xacml;
			this.staplPEP = stapl;
		}
		
		@Override
		public ApplicationPDPMgmtRemote getPDPMgmt(String name) {
			if("STAPL".equals(name))
				return staplPEP;
			else if("XACML".equals(name))
				return xacmlPEP;
			else throw new IllegalArgumentException("Unknown name: " + name);
		}
		
		@Override
		public Map<String, ApplicationPDPMgmtRemote> getAll() {
			final HashMap<String, ApplicationPDPMgmtRemote> map = new HashMap<String, ApplicationPDPMgmtRemote>(2);
			map.put("STAPL", staplPEP);
			map.put("XACML", xacmlPEP);
			
			return map;
		}
		
		@Override
		public Set<String> getSupportedNames() {
			return new HashSet<String>(Arrays.asList("XACML", "STAPL"));
		}
		
		/*@Override
		public String getId() {
			return "" + hashCode();
		}*/

		/*@Override
		public String getStatus() {
			try {
				return "XACML:" + xacmlPEP.getStatus() + " - STAPL:" + staplPEP.getStatus();
			} catch (RemoteException e) {
				return "Remote Exception :'(";
			}
		}*/
		
		@Override
		public boolean equals(Object o) {
			if(o == null)
				return false;
			if(!(o instanceof PDPMgmtHelperImpl))
				return false;
			final PDPMgmtHelperImpl that = (PDPMgmtHelperImpl) o;
			return this.staplPEP == that.staplPEP && this.xacmlPEP == that.xacmlPEP;
		}
		
		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((staplPEP == null) ? 0 : staplPEP.hashCode());
			result = prime * result + ((xacmlPEP == null) ? 0 : xacmlPEP.hashCode());
			return result;
		}
	}
}
