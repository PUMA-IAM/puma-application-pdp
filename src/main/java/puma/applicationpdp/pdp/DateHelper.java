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

import java.util.Calendar;
import java.util.Date;

/**
 * Helper class for handling dates in the policy.
 * 
 * Now = 2013-04-02 14:18:22
 *  
 * @author Maarten Decat
 *
 */
public class DateHelper {

	private Calendar cal;
	
	public DateHelper() {
		this.cal = Calendar.getInstance();
	}
	
	public Date now() {
		cal.clear();
		cal.set(2013, Calendar.APRIL, 2, 14, 18, 22);
		return cal.getTime();
	}
	
	public Date normalShiftStart() {
		cal.clear();
		cal.set(2013, Calendar.APRIL, 2, 8, 30, 00);
		return cal.getTime();
	}
	
	public Date normalShiftStop() {
		cal.clear();
		cal.set(2013, Calendar.APRIL, 2, 17, 00, 00);
		return cal.getTime();
	}
	
	public Date earlyShiftStart() {
		cal.clear();
		cal.set(2013, Calendar.APRIL, 1, 22, 00, 00);
		return cal.getTime();
	}
	
	public Date earlyShiftStop() {
		return normalShiftStart();
	}
	
	public Date lateShiftStart() {
		return normalShiftStop();
	}
	
	public Date lateShiftStop() {
		cal.clear();
		cal.set(2013, Calendar.APRIL, 2, 22, 00, 00);
		return cal.getTime();
	}
	
	public Date yesterday() {
		return daysAgo(1);
	}
	
	public Date threeDaysAgo() {
		return daysAgo(3);
	}
	
	public Date fiveDaysAgo() {
		return daysAgo(5);
	}
	
	public Date twoWeeksAgo() {
		return daysAgo(14);
	}
	
	public Date daysAgo(int amount) {
		now();
		cal.roll(Calendar.DATE, -1 * amount);
		return cal.getTime();
	}
}
