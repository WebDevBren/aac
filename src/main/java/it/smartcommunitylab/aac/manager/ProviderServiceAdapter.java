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

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.JAXBException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import it.smartcommunitylab.aac.Config;
import it.smartcommunitylab.aac.model.Attribute;
import it.smartcommunitylab.aac.model.Authority;
import it.smartcommunitylab.aac.model.SocialEngineException;
import it.smartcommunitylab.aac.model.User;
import it.smartcommunitylab.aac.repository.AttributeRepository;
import it.smartcommunitylab.aac.repository.AuthorityRepository;
import it.smartcommunitylab.aac.repository.UserRepository;

/**
 * This class manages operations of the service
 * 
 */
@Component
@Transactional
public class ProviderServiceAdapter {

	@Autowired
	private AttributesAdapter attrAdapter;
	@Autowired
	private AuthorityRepository authorityRepository;
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private AttributeRepository attributeRepository;

	private SocialEngine socialEngine = new DefaultSocialEngine();
	
	
	@PostConstruct
	private void init() throws JAXBException, IOException {
		attrAdapter.init();
	}

	/**
	 * Updates of user attributes using the values obtained from http request
	 * 
	 * @param authorityUrl
	 *            the url of authority used from user to authenticate himself
	 * @param map 
	 * @param req
	 *            the http request
	 * @return the authentication token of the user (renew if it's expired)
	 * @throws AcServiceException
	 */
	public User updateUser(String authorityUrl, Map<String, String> map, HttpServletRequest req) {
		Authority auth = authorityRepository.findByRedirectUrl(authorityUrl);
		if (auth == null) {
			throw new IllegalArgumentException("Unknown authority URL: " + authorityUrl);
		}
		// read received attribute values
		Map<String, String> attributes = attrAdapter.getAttributes(auth.getName(), map, req);
		List<Attribute> list = extractIdentityAttributes(auth, attributes, true);
		
		// find user by identity attributes
		List<User> users = userRepository.getUsersByAttributes(list);
		if (users == null)
			users = new ArrayList<User>();
		if (users.size() > 1) {
			list = extractIdentityAttributes(auth, attributes, false);
			users = userRepository.getUsersByAttributes(list);
			if (users == null) users = new ArrayList<User>();
			if (users.size() > 1) {
				throw new IllegalArgumentException("The request attributes identify more than one user");
			}
		}
		// fillin attribute list
		list.clear();
		populateAttributes(auth, attributes, list, users.isEmpty() ? null : users.get(0).getAttributeEntities());

		User user = null;
		if (users.isEmpty()) {
			String socialId = "1";
			user = new User(socialId, attributes.get(Config.NAME_ATTR), attributes.get(Config.SURNAME_ATTR), new HashSet<Attribute>(list));
			user = userRepository.save(user);
			try {
				socialId = socialEngine.createUser(""+user.getId());
				user.setSocialId(socialId);
				userRepository.save(user);
			} catch (SocialEngineException e) {
				throw new IllegalArgumentException(e.getMessage(),e);
			}
		} else {
			user = users.get(0);
			attributeRepository.deleteInBatch(user.getAttributeEntities());
			user.setAttributeEntities(new HashSet<Attribute>(list));
			user.updateNames(attributes.get(Config.NAME_ATTR), attributes.get(Config.SURNAME_ATTR));
			userRepository.save(user);
		}
		return user;
	}

	private void populateAttributes(Authority auth, Map<String, String> attributes, List<Attribute> list, Set<Attribute> old) {
		for (String key : attributes.keySet()) {
			String value = attributes.get(key);
			Attribute attr = new Attribute();
			attr.setAuthority(auth);
			attr.setKey(key);
			attr.setValue(value);
			list.add(attr);
		}
		if (old != null) {
			for (Attribute a : old) {
				if (!a.getAuthority().equals(auth)) {
					Attribute attr = new Attribute();
					attr.setAuthority(a.getAuthority());
					attr.setKey(a.getKey());
					attr.setValue(a.getValue());
					list.add(attr);
				}
			}
		}
	}

	/**
	 * Extract identity attribute values from all the attributes received for the specified authority.
	 * @param auth
	 * @param attributes
	 * @param all search for all atrribute matches or only for own identity attributes
	 * @return
	 */
	private List<Attribute> extractIdentityAttributes(Authority auth, Map<String, String> attributes, boolean all) {
		return attrAdapter.findAllIdentityAttributes(auth, attributes, all);
	}
}
