/*******************************************************************************
 * Copyright 2012-2013 Trento RISE
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
 ******************************************************************************/

package it.smartcommunitylab.aac.authority;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import it.smartcommunitylab.aac.jaxbmodel.Attributes;
import it.smartcommunitylab.aac.jaxbmodel.AuthorityMapping;

/**
 * Default handler. Extract the attributes as specified by the authority mapping
 * @author raman
 *
 */
public class CASAuthorityHandler implements AuthorityHandler {

	public static final String USERNAME = "username";
	
	@SuppressWarnings("unchecked")
	@Override
	public Map<String, String> extractAttributes(HttpServletRequest request, Map<String,String> map, AuthorityMapping mapping) {
		Map<String, String> attrs = new HashMap<String, String>(); 
		
		CasAuthenticationToken token = (CasAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();
		String username = token.getName();
		Map<String,Object> tokenAttrs = token.getAssertion().getAttributes();
		if (tokenAttrs == null) {
			tokenAttrs = new HashMap<String, Object>();
		}
		tokenAttrs.put(USERNAME, username);
		
		for (String key : mapping.getIdentifyingAttributes()) {
			Object value = readAttribute(key, tokenAttrs);
			if (value != null) {
				attrs.put(key, value.toString());
			}
		}
		for (Attributes attribute : mapping.getAttributes()) {
			// used alias if present to set attribute in map
			String key = (attribute.getAlias() != null && !attribute.getAlias()
					.isEmpty()) ? attribute.getAlias() : attribute.getValue();
			Object value = readAttribute(attribute.getValue(), tokenAttrs);
			if (value != null) {
				attrs.put(key, value.toString());
			}
		}
		return attrs;
	}

	/**
	 * Read attribute from the map
	 * @param request
	 * @param key
	 * @param useParams whether to extract parameter instead of attribute 
	 * @return
	 */
	private Object readAttribute(String key, Map<String, Object> attrs) {
		Object param = attrs.get(key);
		return param;
	}

}
