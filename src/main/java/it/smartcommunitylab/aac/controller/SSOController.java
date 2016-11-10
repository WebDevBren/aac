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

package it.smartcommunitylab.aac.controller;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import it.smartcommunitylab.aac.manager.AdminManager;
import it.smartcommunitylab.aac.manager.AttributesAdapter;
import it.smartcommunitylab.aac.manager.ClientDetailsManager;
import it.smartcommunitylab.aac.model.User;
import it.smartcommunitylab.aac.repository.UserRepository;

/**
 * Controller for performing the basic operations over the 
 * client apps.
 * @author raman
 *
 */
@Controller
@Transactional
public class SSOController extends AbstractController {

	private Log logger = LogFactory.getLog(getClass());
	
	@Autowired
	private ClientDetailsManager clientDetailsAdapter;
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private AttributesAdapter attributesAdapter;
	@Autowired
	private AdminManager adminManager;

	/**
	 * Retrieve the with the user data: currently on the username is added.
	 * @return
	 */
	@RequestMapping("/sso")
	public ModelAndView sso() {
		User user =  userRepository.findOne(getUserId());
		Map<String,Object> model = new HashMap<String, Object>();
		
		String username = getUserName(user);
		model.put("username",username);
		return new ModelAndView("sso-success", model);
	}

}
