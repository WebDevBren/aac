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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;

import javax.annotation.PostConstruct;

import org.codehaus.jackson.map.DeserializationConfig;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;

import it.smartcommunitylab.aac.auth.fb.FBUser;

/**
 * A helper class for Google's OAuth2 authentication API.
 * 
 * @version 20130224
 * @author Matyas Danter
 * 
 *         Modified by Giulia Canobbio.
 */
@Service("googleHelper")
public final class GoogleAuthHelper {

	@Value("${google.clientId}")
	private String clientId;

	@Value("${google.clientSecret}")
	private String clientSecret;

	@Value("${google.callbackURI}")
	private String callbackURI;

	// google authentication constants
	private static final Iterable<String> SCOPE = Arrays
			.asList("https://www.googleapis.com/auth/userinfo.profile;https://www.googleapis.com/auth/userinfo.email;https://www.googleapis.com/auth/plus.me"
					.split(";"));
	private static final String USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo";
	private static final JsonFactory JSON_FACTORY = new com.google.api.client.json.jackson2.JacksonFactory();
	private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

	private GoogleAuthorizationCodeFlow flow;

	public static final String SESSION_GOOGLE_CHECK = "google-login";

	@SuppressWarnings("unused")
	@PostConstruct
	private void init() {
		flow = new GoogleAuthorizationCodeFlow.Builder(HTTP_TRANSPORT,
				JSON_FACTORY, clientId, clientSecret,
				(Collection<String>) SCOPE).build();
	}

	/**
	 * Builds a login URL based on client ID, secret, callback URI, and scope.
	 */
	public GoogleAuthorizationCodeRequestUrl buildLoginUrl() {
		final GoogleAuthorizationCodeRequestUrl url = flow
				.newAuthorizationUrl();
		return url.setRedirectUri(callbackURI).setState(generateStateToken());
	}

	/**
	 * Generates a secure state token.
	 */
	private String generateStateToken() {
		SecureRandom sr1 = new SecureRandom();
		return "google;" + sr1.nextInt();
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
	public GoogleUser getUserInfoJson(final String authCode) throws IOException {

		final GoogleTokenResponse response = flow.newTokenRequest(authCode)
				.setRedirectUri(callbackURI).execute();
		final Credential credential = flow.createAndStoreCredential(response,
				null);
		final HttpRequestFactory requestFactory = HTTP_TRANSPORT
				.createRequestFactory(credential);

		// Make an authenticated request
		final GenericUrl url = new GenericUrl(USER_INFO_URL);
		final HttpRequest request = requestFactory.buildGetRequest(url);
		request.getHeaders().setContentType("application/json");

		final String jsonIdentity = request.execute().parseAsString();

		ObjectMapper obMapper = new ObjectMapper();
		obMapper.disable(DeserializationConfig.Feature.FAIL_ON_UNKNOWN_PROPERTIES);
		GoogleUser user = obMapper.readValue(jsonIdentity, GoogleUser.class);

		return user;

	}
}