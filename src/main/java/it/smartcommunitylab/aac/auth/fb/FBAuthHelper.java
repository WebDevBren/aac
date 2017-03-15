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
package it.smartcommunitylab.aac.auth.fb;

import java.io.IOException;

import javax.annotation.PostConstruct;

import org.codehaus.jackson.map.DeserializationConfig;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.github.scribejava.apis.FacebookApi;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Token;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.model.Verifier;
import com.github.scribejava.core.oauth.OAuth20Service;

/**
 * A helper class for FB's OAuth2 authentication API.
 * 
 * @version 20130224
 * @author Matyas Danter
 */
@Service("fbHelper")
public final class FBAuthHelper {

	@Value("${fb.clientId}")
	private String clientId;

	@Value("${fb.clientSecret}")
	private String clientSecret;

	@Value("${fb.callbackURI}")
	private String callbackURI;

	private OAuth20Service service;

	public static final String SESSION_FB_CHECK = "fb-login";

	@PostConstruct
	private void init() {
		if (StringUtils.hasText(clientId) && StringUtils.hasText(clientSecret)) {
			service = new ServiceBuilder()
	        .apiKey(clientId)
	        .apiSecret(clientSecret)
	        .callback(callbackURI)
	        .scope("public_profile,email")
	        .build(FacebookApi.instance());
		}
	}

	/**
	 * Builds a login URL based on client ID, secret, callback URI, and scope.
	 */
	public String buildLoginUrl() {
		return service.getAuthorizationUrl();
	}

	/**
	 * Expects an Authentication Code, and makes an authenticated request for
	 * the user's profile information.
	 * 
	 * @param authCode
	 *            : String, authentication code provided by google
	 * @return {@link FBUser} formatted user profile information
	 * @throws IOException
	 */
	public FBUser getUserInfoJson(final String authCode) throws IOException {
		Verifier verifier = new Verifier(authCode);
		Token token = service.getAccessToken(verifier);
		OAuthRequest request = new OAuthRequest(Verb.GET, "https://graph.facebook.com/v2.2/me?fields=name,first_name,last_name,picture,email", service);
		service.signRequest(token, request);;
		Response response = request.send();
		
		ObjectMapper obMapper = new ObjectMapper();
		obMapper.disable(DeserializationConfig.Feature.FAIL_ON_UNKNOWN_PROPERTIES);
		FBUser user = obMapper.readValue(response.getBody(), FBUser.class);

		return user;

	}
}