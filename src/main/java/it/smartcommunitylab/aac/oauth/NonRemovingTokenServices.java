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

package it.smartcommunitylab.aac.oauth;

import java.util.Date;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.Logger;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * @author raman
 *
 */
@Transactional
public class NonRemovingTokenServices extends DefaultTokenServices {

	private ExtTokenStore localtokenStore;

	private Log logger = LogFactory.getLog(getClass());
	private static final Logger traceUserLogger = Logger.getLogger("traceUserToken");

	/** threshold for access token */
	protected int tokenThreshold = 10*60;
	
	/**
	 * Do not remove access token if expired
	 */
	@Override
	public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException {
		OAuth2AccessToken accessToken = localtokenStore.readAccessToken(accessTokenValue);
		if (accessToken == null) {
			throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
		}
		else if (accessToken.isExpired()) {
			logger.error("Accessing expired token: "+accessTokenValue);
			throw new InvalidTokenException("Access token expired: " + accessTokenValue);
		}

		OAuth2Authentication result = localtokenStore.readAuthentication(accessToken);
		return result;
	}

	@Transactional(propagation=Propagation.REQUIRES_NEW, isolation=Isolation.SERIALIZABLE)
	public OAuth2AccessToken refreshAccessToken(String refreshTokenValue, AuthorizationRequest request) throws AuthenticationException {
		return refreshWithRepeat(refreshTokenValue, request, false);
	}

	private OAuth2AccessToken refreshWithRepeat(String refreshTokenValue, AuthorizationRequest request, boolean repeat) {
		OAuth2AccessToken accessToken = localtokenStore.readAccessTokenForRefreshToken(refreshTokenValue);
		if (accessToken == null) {
			throw new InvalidGrantException("Invalid refresh token: " + refreshTokenValue);
		}

		if (accessToken.getExpiration().getTime() -System.currentTimeMillis() > tokenThreshold*1000L ) {
			return accessToken;
		}

		try {
			OAuth2AccessToken res = super.refreshAccessToken(refreshTokenValue, request);
			OAuth2Authentication auth = localtokenStore.readAuthentication(res);
			traceUserLogger.info(String.format("'type':'refresh','user':'%s','token':'%s'", auth.getName(), res.getValue()));
			return res;
		} catch (RuntimeException e) {
			// do retry: it may be the case of race condition so retry the operation but only once
			if (!repeat) return refreshWithRepeat(refreshTokenValue, request, true);
			throw e;
		}
	}

	@Transactional(isolation=Isolation.SERIALIZABLE)
	public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
		OAuth2AccessToken existingAccessToken = localtokenStore.getAccessToken(authentication);
		OAuth2RefreshToken refreshToken = null;
		if (existingAccessToken != null) {
			if (existingAccessToken.isExpired()) {
				if (existingAccessToken.getRefreshToken() != null) {
					refreshToken = existingAccessToken.getRefreshToken();
					// The token store could remove the refresh token when the access token is removed, but we want to
					// be sure...
					localtokenStore.removeRefreshToken(refreshToken);
				}
				localtokenStore.removeAccessToken(existingAccessToken);
			}
			else {
				return existingAccessToken;
			}
		}

		// Only create a new refresh token if there wasn't an existing one associated with an expired access token.
		// Clients might be holding existing refresh tokens, so we re-use it in the case that the old access token
		// expired.
		if (refreshToken == null) {
			refreshToken = createRefreshToken(authentication);
		}
		// But the refresh token itself might need to be re-issued if it has expired.
		else if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
			ExpiringOAuth2RefreshToken expiring = (ExpiringOAuth2RefreshToken) refreshToken;
			if (isExpired(expiring)) {
				refreshToken = createRefreshToken(authentication);
			}
		}

		OAuth2AccessToken accessToken = createAccessToken(authentication, refreshToken);
		localtokenStore.storeAccessToken(accessToken, authentication);
		if (refreshToken != null) {
			localtokenStore.storeRefreshToken(refreshToken, authentication);
		}
		traceUserLogger.info(String.format("'type':'new','user':'%s','token':'%s'", authentication.getName(), accessToken.getValue()));
		return accessToken;
	}
	
	private ExpiringOAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication) {
		if (!isSupportRefreshToken(authentication.getAuthorizationRequest())) {
			return null;
		}
		int validitySeconds = getRefreshTokenValiditySeconds(authentication.getAuthorizationRequest());
		ExpiringOAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken(UUID.randomUUID().toString(),
				new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));
		return refreshToken;
	}

	private OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken) {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(UUID.randomUUID().toString());
		int validitySeconds = getAccessTokenValiditySeconds(authentication.getAuthorizationRequest());
		if (validitySeconds > 0) {
			token.setExpiration(new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));
		}
		token.setRefreshToken(refreshToken);
		token.setScope(authentication.getAuthorizationRequest().getScope());

		return token;
	}
	@Override
	public void setTokenStore(TokenStore tokenStore) {
		super.setTokenStore(tokenStore);
		assert tokenStore instanceof ExtTokenStore;
		this.localtokenStore = (ExtTokenStore)tokenStore;
	}

	/**
	 * @param tokenThreshold the tokenThreshold to set
	 */
	public void setTokenThreshold(int tokenThreshold) {
		this.tokenThreshold = tokenThreshold;
	}
	
	@Override
	protected boolean isExpired(OAuth2RefreshToken refreshToken) {
		return false;
	}
	
	
}
