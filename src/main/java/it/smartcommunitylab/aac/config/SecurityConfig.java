package it.smartcommunitylab.aac.config;

import it.smartcommunitylab.aac.auth.fb.FBFilter;
import it.smartcommunitylab.aac.auth.google.GoogleProviderFilter;
import it.smartcommunitylab.aac.auth.internal.InternalRegFilter;
import it.smartcommunitylab.aac.oauth.InternalUserDetailsRepo;

import java.beans.PropertyVetoException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

import eu.trentorise.smartcampus.resourceprovider.filter.ResourceFilter;

@Configuration 
@EnableAuthorizationServer
public class SecurityConfig {

	@Autowired
	private Environment env;
	
	@Autowired
	private JdbcClientDetailsService clientDetailsService;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(getClientDetailsUserService());
		auth.userDetailsService(getInternalUserDetailsService());
		// password-encoder???
	}	
	
	@Bean
	public InternalUserDetailsRepo getInternalUserDetailsService() {
		return new InternalUserDetailsRepo();
	}	
	
	@Bean
	public PasswordEncoder getInternalPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}	
	
	@Bean
	public ClientDetailsUserDetailsService getClientDetailsUserService() throws PropertyVetoException {
		ClientDetailsUserDetailsService bean = new ClientDetailsUserDetailsService(clientDetailsService);
		return bean;
	}	
	
// where needed	
//	@Bean
//	public ClientCredentialsTokenEndpointFilter getClientCredentialsTokenEndpointFilter() throws Exception {
//		ClientCredentialsTokenEndpointFilter bean = new ClientCredentialsTokenEndpointFilter();
//		bean.setAuthenticationManager(authenticationManagerBean());
//		return bean;
//	}
	
	@Bean
	public OAuth2AuthenticationEntryPoint getClientAuthenticationEntryPoint() {
		return new OAuth2AuthenticationEntryPoint();
	}
	
	@Bean
	public Http403ForbiddenEntryPoint getForbEntryPoint() {
		return new Http403ForbiddenEntryPoint();
	}
	
	@Bean
	public OAuth2AccessDeniedHandler getOauthAccessDeniedHandler() {
		return new OAuth2AccessDeniedHandler();
	}	
	
	@Bean
	public GoogleProviderFilter getGoogleProviderFilter() {
		return new GoogleProviderFilter();
	}
	
	@Bean
	public FBFilter getFBFilter() {
		return new FBFilter();
	}	
	
	@Bean
	public InternalRegFilter getInternalRegFilter() {
		return new InternalRegFilter();
	}		
	
	@Bean
	public ResourceFilter getResourceFilter() throws PropertyVetoException {
		ResourceFilter bean = new ResourceFilter();
		bean.setAuthenticationManager(authenticationManager);
		return bean;
	}	
	
	@Configuration
	@Order(10)
	public static class BasicProfileSecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		private ResourceFilter resourceFilter;

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.csrf().disable();
			http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

			http.antMatcher("/basicprofile/**").authorizeRequests().antMatchers("/basicprofile/**").fullyAuthenticated().and()
			.addFilterBefore(resourceFilter, RequestHeaderAuthenticationFilter.class);
		}

	}

	@Configuration
	@Order(100)
	public static class ConsoleSecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		private ResourceFilter resourceFilter;

		@Override
		public void configure(HttpSecurity http) throws Exception {
    		http.csrf().disable();
    		http.rememberMe();		

    		http.authorizeRequests().antMatchers("/dev/**","/oauth/**").hasAnyAuthority("ROLE_CONSOLE").and()
    		.formLogin().loginPage("/eauth/dev").permitAll().and().logout().permitAll();
//    		.formLogin().loginPage("/eauth/dev").permitAll().and().logout().invalidateHttpSession(true).deleteCookies("JSESSIONID","open_id_session_id","vasdevgoogle").logoutUrl("/logout").logoutSuccessUrl("/dev").permitAll();
		}

	}	
	
	
	
//	  <sec:http disable-url-rewriting="true">
//      <sec:intercept-url pattern="/dev/**" access="IS_AUTHENTICATED_FULLY" />
//      <sec:intercept-url pattern="/oauth/**" access="IS_AUTHENTICATED_FULLY" />
//      <sec:form-login login-page="/eauth/dev" />
//      <sec:logout invalidate-session="true" logout-url="/logout" delete-cookies="JSESSIONID,open_id_session_id,vasdevgoogle" logout-success-url="/dev"/>
//  </sec:http>	
    
    @Configuration
    @Order(1000)                                                        
    public static class NoSecurityConfig extends WebSecurityConfigurerAdapter {
    
    	@Override
    	protected void configure(HttpSecurity http) throws Exception {
    		http.csrf().disable();
    		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    		http.authorizeRequests().antMatchers("/**").anonymous().anyRequest().permitAll();

    	} 	
    	
    }      
    
    
    
	
}
