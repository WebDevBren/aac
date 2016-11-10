package it.smartcommunitylab.aac.oauth;

import java.io.IOException;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;

import it.smartcommunitylab.aac.Config;
import it.smartcommunitylab.aac.model.ClientAppInfo;
import it.smartcommunitylab.aac.model.ClientDetailsEntity;
import it.smartcommunitylab.aac.repository.ClientDetailsRepository;

/**
 * Filter for the client credential token acquisition. Extends the standard behaviour
 * in case of authorization code flow by checking also the 'mobile' client secret against
 * the requested one.
 * @author raman
 *
 */
public class ClientCredentialsTokenEndpointFilter extends
	org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter {

	@Autowired
	private ClientDetailsRepository clientDetailsRepository = null;


	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

		String clientId = request.getParameter("client_id");
		String clientSecret = request.getParameter("client_secret");

		// If the request is already authenticated we can assume that this filter is not needed
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication != null && authentication.isAuthenticated()) {
			return authentication;
		}
		
		if (clientId == null) {
			throw new BadCredentialsException("No client credentials presented");
		}

		if (clientSecret == null) {
			clientSecret = "";
		}

		clientId = clientId.trim();

		String grant_type = request.getParameter("grant_type");
		if ("implicit".equals(grant_type)) {
			throw new InvalidGrantException("Invalid grant type for token endpoint: " + grant_type);
		}

		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(clientId, clientSecret);
		if ("authorization_code".equals(grant_type) || "refresh_token".equals(grant_type) || "password".equals(grant_type)) {
			
			ClientDetailsEntity clientDetails = clientDetailsRepository.findByClientId(clientId);
			Set<String> grantTypes = clientDetails.getAuthorizedGrantTypes();
			if (grantTypes == null || !grantTypes.contains(grant_type)) {
				// check if trusted client
				if ("password".equals(grant_type)) {
					boolean isTrusted = false;
					if (clientDetails.getAuthorities() != null) {
						for (GrantedAuthority ga : clientDetails.getAuthorities())
							if (Config.AUTHORITY.ROLE_CLIENT_TRUSTED.toString().equals(ga.getAuthority())) {
								isTrusted = true;
								break;
							}
					}
					if (!isTrusted) {
						throw new InvalidGrantException("Unauthorized grant type: " + grant_type);
					}
				} else{
					throw new InvalidGrantException("Unauthorized grant type: " + grant_type);
				}
			}
			
			String clientSecretServer = clientDetails.getClientSecret();
			ClientAppInfo info = ClientAppInfo.convert(clientDetails.getAdditionalInformation());
			String clientSecretMobile = clientDetails.getClientSecretMobile();
			if (clientSecretMobile.equals(clientSecret) && !info.isNativeAppsAccess()) {
				throw new InvalidGrantException("Native app access is not enabled");
			}
			// TODO Check the native app hash
			
			if (!clientSecretServer.equals(clientSecret) && !clientSecretMobile.equals(clientSecret)) {
                throw new BadCredentialsException(messages.getMessage(
                        "AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
			}
			
			
			User user = new User(clientId, clientSecret, clientDetails.getAuthorities());

	        UsernamePasswordAuthenticationToken result = 
	        		new UsernamePasswordAuthenticationToken(user,
	                authRequest.getCredentials(), user.getAuthorities());
	        result.setDetails(authRequest.getDetails());
	        return result;

		}
		return this.getAuthenticationManager().authenticate(authRequest);
	}


	
	
}
