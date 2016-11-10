/**
 *    Copyright 2012-2013 Trento RISE
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
 */

package it.smartcommunitylab.aac.manager;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import it.smartcommunitylab.aac.model.Identity;

/**
 * Used to check whether the user has the administrator rights.
 * @author raman
 *
 */
@Component
public class AdminManager {

	@Autowired
	@Value("${ac.admin.file}")
	private Resource adminFile;
	
	public enum ROLE {admin, user, developer, manager};
	
	
	public boolean checkAccount(Set<Identity> identityStrings, ROLE role) throws Exception {
		BufferedReader reader = new BufferedReader(new InputStreamReader(adminFile.getInputStream()));
		String line = null;
		while ((line = reader.readLine()) != null) {
			if (line.startsWith("#")) continue;

			String[] arr = line.split(";");
			if (arr.length != 4) continue;
				
			Identity test = new Identity(arr[0].trim(), arr[1].trim(), arr[2].trim());
			if (role.name().equals(arr[3].trim()) && identityStrings.contains(test)) return true;
		}
		return false;
	}
}
