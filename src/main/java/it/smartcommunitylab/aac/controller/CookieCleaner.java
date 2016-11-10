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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 * @author raman
 *
 */
public class CookieCleaner implements LogoutSuccessHandler {

	private String[] cookieNames;
	private String redirect;
	
	/**
	 * @param cookiePrefixes
	 */
	public CookieCleaner(String cookiePrefixes, String redirect) {
		super();
		this.cookieNames = cookiePrefixes.split(",");
		this.redirect = redirect;
	}

	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		for (String s : cookieNames) {
            Cookie cookie = new Cookie(s, null);
            cookie.setPath("/");
            cookie.setMaxAge(0);
            response.addCookie(cookie);

            cookie = new Cookie(s, null);
            cookie.setPath(request.getContextPath()+ "/eauth/");
            cookie.setMaxAge(0);
            response.addCookie(cookie);
		}

		if (request.getCookies() != null) {
			for (int i = 0; i < request.getCookies().length; i++) {
				Cookie cookie = request.getCookies()[i];
				for (String s : cookieNames) {
					if (cookie.getName().startsWith(s)) {
			            cookie = new Cookie(cookie.getName(), null);
			            cookie.setPath("/");
			            cookie.setMaxAge(0);
			            response.addCookie(cookie);

						cookie = new Cookie(cookie.getName(), null);
			            cookie.setPath(request.getContextPath()+"/eauth/");
			            cookie.setMaxAge(0);
			            response.addCookie(cookie);
					}
				}
			}
		}
		request.getSession().invalidate();
		if (authentication != null) authentication.setAuthenticated(false);
		response.sendRedirect(request.getContextPath()+redirect);
	}

}
