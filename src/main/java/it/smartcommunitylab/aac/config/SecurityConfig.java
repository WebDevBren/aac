package it.smartcommunitylab.aac.config;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.filter.CompositeFilter;

import it.smartcommunitylab.aac.common.Utils;
import it.smartcommunitylab.aac.config.SecurityConfig.OAuthProviders.ClientResources;
import it.smartcommunitylab.aac.oauth.ExtOAuth2SuccessHandler;

@Configuration 
@EnableOAuth2Client
//@EnableOAuth2Sso
@EnableAuthorizationServer
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${application.url}")
	private String applicationURL;

	@Autowired
	OAuth2ClientContext oauth2ClientContext;

	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

	@Bean
	@ConfigurationProperties("oauth-providers")
	public OAuthProviders oauthProviders(){
		return new OAuthProviders();
	}
	
	private Filter ssoFilter() {
		CompositeFilter filter = new CompositeFilter();
		List<Filter> filters = new ArrayList<>();
		List<ClientResources> providers = oauthProviders().getProviders();
		for (ClientResources client : providers) {
			String id = client.getProvider();
			filters.add(ssoFilter(client, Utils.filterRedirectURL(id), "/eauth/"+id));
		}
		filter.setFilters(filters);
		return filter;
	}	
	
	private Filter ssoFilter(ClientResources client, String path, String target) {
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(
				path);
		
		filter.setAuthenticationSuccessHandler(new ExtOAuth2SuccessHandler(target));
		
		OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
		filter.setRestTemplate(template);
		UserInfoTokenServices tokenServices = new UserInfoTokenServices(
				client.getResource().getUserInfoUri(), client.getClient().getClientId());
		tokenServices.setRestTemplate(template);
		filter.setTokenServices(tokenServices);
		return filter;
	}	
	
	
	static public class OAuthProviders {
		@NestedConfigurationProperty
		private List<ClientResources> providers;

		public List<ClientResources> getProviders() {
			return providers;
		}

		public void setProviders(List<ClientResources> providers) {
			this.providers = providers;
		}
		public static class ClientResources {

			private String provider;
			
			@NestedConfigurationProperty
			private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

			@NestedConfigurationProperty
			private ResourceServerProperties resource = new ResourceServerProperties();

			public String getProvider() {
				return provider;
			}

			public void setProvider(String provider) {
				this.provider = provider;
			}

			public AuthorizationCodeResourceDetails getClient() {
				return client;
			}

			public ResourceServerProperties getResource() {
				return resource;
			}
		}	
	}
	
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
//		http.csrf().disable();
//
//		http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**").permitAll().anyRequest()
//		.authenticated().and()
//		.authorizeRequests().antMatchers("/dev/**","/oauth/**").fullyAuthenticated().and()
//		.formLogin().loginPage("/eauth/dev").permitAll().and().logout().permitAll();
		

//		http.antMatcher("/**").authorizeRequests().antMatchers("/", "/dev/**").permitAll().anyRequest()
//		.authenticated().and().exceptionHandling()
//		.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/dev")).and().logout()
//		.logoutSuccessUrl("/").permitAll().and().csrf()
//		.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
//		.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);		
		
		http.authorizeRequests().antMatchers("/dev/**","/oauth/**").fullyAuthenticated().and().exceptionHandling()
		.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/eauth/dev")).and().logout()
		.logoutSuccessUrl("/").permitAll().and().csrf()
		.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
		.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
	
		
		
	}
	
}
