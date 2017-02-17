package it.smartcommunitylab.aac.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.Filter;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CompositeFilter;

import it.smartcommunitylab.aac.common.Utils;
import it.smartcommunitylab.aac.oauth.ContextExtender;
import it.smartcommunitylab.aac.oauth.ExtOAuth2SuccessHandler;
import it.smartcommunitylab.aac.oauth.OAuthProviders;
import it.smartcommunitylab.aac.oauth.OAuthProviders.ClientResources;
import it.smartcommunitylab.aac.oauth.UserApprovalHandler;

@Configuration 
@EnableOAuth2Client
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
	
	
	@Override
	public void configure(HttpSecurity http) throws Exception {		
		http
			.authorizeRequests()
				.antMatchers("/dev/**","/oauth/**").authenticated()
				.and().exceptionHandling()
					.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/eauth/dev"))
				.and().logout()
					.logoutSuccessUrl("/").permitAll()
				.and().csrf()
					.disable()
					.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
	}
	
	
	@Override
	@Bean("authenticationManagerBean")
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	protected ContextExtender contextExtender() {
		return new ContextExtender();
	}
	
	@Configuration
	@EnableAuthorizationServer
	protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
		@Autowired
		private TokenStore tokenStore;

		@Autowired
		private UserApprovalHandler userApprovalHandler;

		@Autowired
		@Qualifier("authenticationManagerBean")
		private AuthenticationManager authenticationManager;

		@Autowired
		private DataSource dataSource;
		@Autowired
		private ClientDetailsService clientDetailsService;
		
		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients.jdbc(dataSource).clients(clientDetailsService);
		}
		
		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.tokenStore(tokenStore).userApprovalHandler(userApprovalHandler)
					.authenticationManager(authenticationManager);
		}		
        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
            oauthServer.allowFormAuthenticationForClients();
        }
    }
	
	@Bean
	protected ResourceServerConfiguration profileResources() {
		ResourceServerConfiguration resource = new ResourceServerConfiguration() {	
			public void setConfigurers(List<ResourceServerConfigurer> configurers) {
				super.setConfigurers(configurers);
			}
		};
		resource.setConfigurers(Arrays.<ResourceServerConfigurer> asList(new ResourceServerConfigurerAdapter() {
			public void configure(ResourceServerSecurityConfigurer resources) throws Exception { resources.resourceId(null); }
			public void configure(HttpSecurity http) throws Exception {
				http
				.antMatcher("/*profile/**")
				.authorizeRequests()
				.antMatchers("/basicprofile/all").access("#oauth2.hasScope('profile.basicprofile.all')")
				.antMatchers("/basicprofile/me").access("#oauth2.hasScope('profile.basicprofile.me')")
				.antMatchers("/accountprofile/all").access("#oauth2.hasScope('profile.accountprofile.all')")
				.antMatchers("/accountprofile/me").access("#oauth2.hasScope('profile.accountprofile.me')")
				.and().csrf().disable();
			}

		}));
		resource.setOrder(4);
		return resource;
	}
	
}
