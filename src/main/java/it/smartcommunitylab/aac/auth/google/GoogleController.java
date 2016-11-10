/*******************************************************************************
 * Copyright 2012-2013 Trento RISE
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package it.smartcommunitylab.aac.auth.google;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;

/**
 * Google controller connects to google and retrieve user data.
 * 
 * @author Giulia Canobbio
 * 
 */
@Controller
@RequestMapping(value = "/auth/google-oauth")
public class GoogleController {

	private static final Logger logger = LoggerFactory
			.getLogger(GoogleController.class);

	private static final String SESSION_ATTR_STATE = "state";
	/**
	 * Instance of {@link GoogleAuthHelper} for oauth google
	 */
	@Autowired
	private GoogleAuthHelper auth;

	/**
	 * This rest web services sends an authentication request to Google. First
	 * it creates state token and then it builds login url for Google. After
	 * that state token is saved in current session.
	 * 
	 * @param response
	 *            : instance of {@link HttpServletResponse}
	 * @param request
	 *            : instance of {@link HttpServletRequest}
	 * @return {@link ResponseObject} with redirect google login url, status
	 *         (OK)
	 */
	@RequestMapping(method = RequestMethod.GET)
	public String socialGooglePlus(HttpServletResponse response,
			HttpServletRequest request) {
		GoogleAuthorizationCodeRequestUrl googleCodeURL = auth.buildLoginUrl();
		request.getSession().setAttribute(SESSION_ATTR_STATE,
				googleCodeURL.getState());
		return "redirect:" + googleCodeURL.build();

	}

	/**
	 * This rest web service is the one that google called after login (callback
	 * url). First it retrieve code and token that google sends back. It checks
	 * if code and token are not null, then if token is the same that was saved
	 * in session. If it is not response status is UNAUTHORIZED, otherwise it
	 * retrieves user data. If user is not already saved in db, then user is
	 * added in db, iff email is not already used, otherwise it sends an
	 * UNAUTHORIZED status and redirect user to home page without authenticating
	 * him/her. If it is all ok, then it authenticates user in spring security
	 * and create cookie user. Then redirects authenticated user to home page
	 * where user can access protected resources.
	 * 
	 * @param request
	 *            : instance of {@link HttpServletRequest}
	 * @param response
	 *            : instance of {@link HttpServletResponse}
	 * @return redirect to home page
	 */
	@RequestMapping(value = "/callback", method = RequestMethod.GET)
	public String confirmStateToken(HttpServletRequest request,
			HttpServletResponse response) {

		String code = request.getParameter("code");
		String token = request.getParameter("state");
		String sessionStateToken = "";
		if (request.getSession().getAttribute(SESSION_ATTR_STATE) != null) {
			sessionStateToken = request.getSession()
					.getAttribute(SESSION_ATTR_STATE).toString();
		}

		// compare state token in session and state token in response of google
		// if equals return to home
		// if not error page
		if ((code == null || token == null)
				&& (!token.equals(sessionStateToken))) {
			logger.error("Error in google authentication flow");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return "";
		} else {
			try {
				GoogleUser userInfo = auth.getUserInfoJson(code);
				response.setStatus(HttpServletResponse.SC_OK);
				request.getSession().setAttribute(
						GoogleAuthHelper.SESSION_GOOGLE_CHECK, "true");
				return String
						.format("redirect:/eauth/google?target=%s&OIDC_CLAIM_email=%s&OIDC_CLAIM_given_name=%s&OIDC_CLAIM_family_name=%s",
								URLEncoder.encode((String) request.getSession()
										.getAttribute("redirect"), "UTF8"),
								userInfo.getEmail(), userInfo.getGivenName(),
								userInfo.getFamilyName());

			} catch (IOException e) {
				logger.error("IOException .. Problem in reading user data.", e);
				response.setStatus(HttpServletResponse.SC_NOT_FOUND);
			}
		}

		return "redirect:/";
	}
}
