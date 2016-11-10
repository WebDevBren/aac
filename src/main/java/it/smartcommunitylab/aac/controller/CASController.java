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

import java.io.ByteArrayOutputStream;
import java.net.URI;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import edu.yale.tp.cas.AttributesType;
import edu.yale.tp.cas.AuthenticationFailureType;
import edu.yale.tp.cas.AuthenticationSuccessType;
import edu.yale.tp.cas.ObjectFactory;
import edu.yale.tp.cas.ServiceResponseType;
import it.smartcommunitylab.aac.cas.CASException;
import it.smartcommunitylab.aac.cas.CASException.ERROR_CODE;
import it.smartcommunitylab.aac.cas.TicketManager;
import it.smartcommunitylab.aac.cas.TicketManager.Ticket;
import it.smartcommunitylab.aac.model.Attribute;
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
public class CASController extends AbstractController {

	private Log logger = LogFactory.getLog(getClass());
	
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private TicketManager ticketManager;

	private static ObjectFactory factory = new ObjectFactory();

	
	/**
	 * After the user authenticated redirect to the requested service URL with the ticket.
	 * @return
	 */
	@RequestMapping("/cas/login")
	public ModelAndView casLogin(HttpServletRequest req, HttpServletResponse res, @RequestParam String service) {
		req.getSession().setAttribute("_service", service);
		return new ModelAndView("redirect:/cas/loginsuccess");
	}

	/**
	 * After the user authenticated redirect to the requested service URL with the ticket.
	 * @return
	 */
	@RequestMapping("/cas/loginsuccess")
	public ModelAndView casLoginsuccess(HttpServletRequest req, HttpServletResponse res, @RequestParam(required=false) String service) {
		try {
			if (service == null) {
				service = (String)req.getSession().getAttribute("_service");
				if (service == null) {
					logger.error("CAS login error: no service URL specified");
					res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
					return new ModelAndView("cas_error");
				}
			}
			
			checkService(req, res, service);
			User user =  userRepository.findOne(getUserId());
			String ticket = ticketManager.getTicket(user.getId().toString(), service);
			return new ModelAndView("redirect:"+service+"?ticket="+ticket);
		} catch (CASException e) {
			logger.error("CAS login error: "+e.getMessage());
			res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return new ModelAndView("redirect:"+service);
		}
	}
	
	/**
	 * Retrieve the with the user data: currently on the username is added.
	 * @return
	 */
	@RequestMapping("/cas/serviceValidate")
	public @ResponseBody String validateService(HttpServletRequest req, HttpServletResponse res, @RequestParam String service, @RequestParam String ticket) {
		try {
			res.setContentType("application/xml");
			checkService(req, res, service);
			Ticket obj = ticketManager.checkTicket(service, ticket);
			User user = userRepository.findOne(Long.parseLong(obj.getId()));
			return generateSuccess(user, obj.isFromNewLogin());//new ModelAndView("redirect:"+service);
		} catch (CASException e) {
			logger.error("CAS login error: "+e.getMessage());
			res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			try {
				return generateFailure(e.getCode().toString(),e.getMessage());
			} catch (Exception e1) {
				logger.error("CAS login error: "+e.getMessage());
				res.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				return null;
			}
		} catch (Exception e) {
			e.printStackTrace();
			logger.error("CAS login error: "+e.getMessage());
			res.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			return null;
		}
		
	}
	/**
	 * @param req
	 * @param res
	 * @param service
	 * @return true if the service is a valid HTTPS URL.
	 */
	private void checkService(HttpServletRequest req, HttpServletResponse res, String service) throws CASException {
		try {
//			URI url = 
			URI.create(service);
//			if (!"https".equals(url.getScheme())) throw new CASException(ERROR_CODE.INVALID_PROXY_CALLBACK, "Non HTTPS callback");
		} catch (Exception e) {
			logger.error("Incorrect service URL : "+service);
			throw new CASException(ERROR_CODE.INVALID_PROXY_CALLBACK, "Invalid callback address");
		}
	}
	
	private static String generateSuccess(User user, boolean isNew) throws Exception {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		ServiceResponseType value = factory.createServiceResponseType();
		
		AuthenticationSuccessType success = factory.createAuthenticationSuccessType();
		success.setUser(""+user.getId());
		AttributesType attrs = factory.createAttributesType();
		attrs.setIsFromNewLogin(isNew);
		attrs.getAny().add(createElement("name", user.getName()));
		attrs.getAny().add(createElement("surname", user.getSurname()));
		if (user.getAttributeEntities() != null) {
			for(Attribute a : user.getAttributeEntities()) {
				attrs.getAny().add(createElement(a.getKey(), a.getValue()));
			} 
		}
		success.setAttributes(attrs);
		value.setAuthenticationSuccess(success);
		
		JAXBElement<ServiceResponseType> createServiceResponse = factory.createServiceResponse(value);
				
		JAXB.marshal(createServiceResponse, os);
		return os.toString();
	}
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
	private static JAXBElement<Object> createElement(String key, String value) {
		return new JAXBElement(new QName("http://www.yale.edu/tp/cas",key, "cas"), String.class,value == null ? "" : value);
	}
	

	/**
	 * @param string
	 * @return
	 * @throws JAXBException 
	 */
	private static String generateFailure(String code, String codeValue) throws Exception {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		ServiceResponseType value = factory.createServiceResponseType();
		
		AuthenticationFailureType failure = factory.createAuthenticationFailureType();
		failure.setValue(codeValue);
		failure.setCode(code);
		value.setAuthenticationFailure(failure);
		JAXBElement<ServiceResponseType> createServiceResponse = factory.createServiceResponse(value);
		
		JAXB.marshal(createServiceResponse, os);

		return os.toString();	
	}
}
