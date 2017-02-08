package it.smartcommunitylab.aac.config;

import it.smartcommunitylab.aac.auth.fb.FBFilter;
import it.smartcommunitylab.aac.auth.google.GoogleProviderFilter;
import it.smartcommunitylab.aac.auth.internal.InternalRegFilter;
import it.smartcommunitylab.aac.authority.AnonymousAuthorityHandler;
import it.smartcommunitylab.aac.authority.AuthorityHandler;
import it.smartcommunitylab.aac.authority.AuthorityHandlerContainer;
import it.smartcommunitylab.aac.authority.DefaultAuthorityHandler;
import it.smartcommunitylab.aac.authority.FBAuthorityHandler;
import it.smartcommunitylab.aac.authority.GoogleAuthorityHandler;
import it.smartcommunitylab.aac.controller.CookieCleaner;
import it.smartcommunitylab.aac.manager.SocialEngine;
import it.smartcommunitylab.aac.model.ClientDetailsRowMapper;
import it.smartcommunitylab.aac.oauth.AutoJdbcAuthorizationCodeServices;
import it.smartcommunitylab.aac.oauth.AutoJdbcTokenStore;
import it.smartcommunitylab.aac.oauth.CachedResourceStorage;
import it.smartcommunitylab.aac.oauth.ClientCredentialsFilter;
import it.smartcommunitylab.aac.oauth.ClientCredentialsTokenEndpointFilter;
import it.smartcommunitylab.aac.oauth.InternalPasswordEncoder;
import it.smartcommunitylab.aac.oauth.IsolationSupportHibernateJpaDialect;
import it.smartcommunitylab.aac.oauth.NonRemovingTokenServices;
import it.smartcommunitylab.aac.oauth.UserApprovalHandler;
import it.smartcommunitylab.aac.oauth.UserDetailsRepo;

import java.beans.PropertyVetoException;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.core.env.Environment;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.data.repository.query.QueryLookupStrategy;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;

import com.google.common.collect.Maps;
import com.mchange.v2.c3p0.ComboPooledDataSource;

import eu.trentorise.smartcampus.resourceprovider.filter.ResourceAuthenticationManager;
import eu.trentorise.smartcampus.resourceprovider.filter.ResourceFilter;
import eu.trentorise.smartcampus.resourceprovider.jdbc.JdbcServices;
//import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;

@Configuration 
@EnableAuthorizationServer
@ComponentScan//("it.smartcommunitylab.aac")
@EntityScan({"it.smartcommunitylab.aac.model", "it.smartcommunitylab.aac.profile.model"})
@EnableWebMvc
@ComponentScan("it.smartcommunitylab.aac")
@PropertySource("classpath:commoncore.properties")
@EnableTransactionManagement
@EnableJpaRepositories(basePackages = {"it.smartcommunitylab.aac.repository"}, queryLookupStrategy = QueryLookupStrategy.Key.CREATE_IF_NOT_FOUND)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private Environment env;
	
	@Autowired
	private UserDetailsService internalUserDetailsRepo;
	
	private static final String[] ENTITYMANAGER_PACKAGES_TO_SCAN = {"it.smartcommunitylab.aac.model"}; // , "it.smartcommunitylab.aac.repository"};
	
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(getClientDetailsUserService());
		auth.userDetailsService(internalUserDetailsRepo);
		// password-encoder???

	}	
	
	@Bean
	public ClientCredentialsFilter getClientCredentialsFilter() throws PropertyVetoException {
		ClientCredentialsFilter ccf = new ClientCredentialsFilter("/internal/register/rest");
		ccf.setAuthenticationManager(getResourceAuthenticationManager());
		return ccf;
	}	

	@Bean
	public ClientDetailsUserDetailsService getClientDetailsUserService() throws PropertyVetoException {
		ClientDetailsUserDetailsService bean = new ClientDetailsUserDetailsService(getClientDetails());
		return bean;
	}
	
//	@Bean
//	public InternalUserDetailsRepo getInternalUserDetailsService() {
//		return new InternalUserDetailsRepo();
//	}	
	
	@Bean
	public UserDetailsRepo getUserDetailsService() {
		return new UserDetailsRepo();
	}
	
//	@Bean
//	@Override
//	// get?
//	public AuthenticationManager authenticationManagerBean() throws Exception {
//		return super.authenticationManagerBean();
//	}	
	
	@Bean
	public AuthenticationManager getResourceAuthenticationManager() throws PropertyVetoException {
		ResourceAuthenticationManager bean = new ResourceAuthenticationManager();
		bean.setTokenStore(getTokenStore());
		bean.setAuthServices(getJdbcServices());
		return bean;
	}
	
	@Bean
	public ResourceFilter getResourceFilter() throws PropertyVetoException {
		ResourceFilter bean = new ResourceFilter();
		bean.setAuthenticationManager(getResourceAuthenticationManager());
		return bean;
	}
	
	@Bean
	public JdbcClientDetailsService getClientDetails() throws PropertyVetoException {
		JdbcClientDetailsService bean = new JdbcClientDetailsService(getDataSource());
		bean.setRowMapper(getClientDetailsRowMapper());
		return bean;
	}

	@Bean
	public ClientDetailsRowMapper getClientDetailsRowMapper() {
		return new ClientDetailsRowMapper();
	}
	
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
	public ClientCredentialsTokenEndpointFilter getClientCredentialsTokenEndpointFilter() throws Exception {
		ClientCredentialsTokenEndpointFilter bean = new ClientCredentialsTokenEndpointFilter();
		bean.setAuthenticationManager(authenticationManagerBean());
		return bean;
	}
	
	@Bean
	public JdbcServices getJdbcServices() throws PropertyVetoException {
		return new JdbcServices(getDataSource());
	}
	
	@Bean 
	public AutoJdbcTokenStore getTokenStore() throws PropertyVetoException {
		return new AutoJdbcTokenStore(getDataSource());
	}
	
	@Bean
	public AutoJdbcAuthorizationCodeServices getAuthorizationCodeServices() throws PropertyVetoException {
		return new AutoJdbcAuthorizationCodeServices(getDataSource());
	}	
	
	@Bean
	public CachedResourceStorage getResourceStorage() {
		return new CachedResourceStorage();
	}
	
	@Bean
	public NonRemovingTokenServices getTokenServices() throws PropertyVetoException {
		NonRemovingTokenServices bean = new NonRemovingTokenServices();
		bean.setTokenStore(getTokenStore());
		bean.setSupportRefreshToken(true);
		bean.setReuseRefreshToken(true);
		bean.setClientDetailsService(getClientDetails());
		return bean;
	}
	
	@Bean
	public UserApprovalHandler getUserApprovalHandler() throws PropertyVetoException {
		UserApprovalHandler bean = new UserApprovalHandler();
//		bean.setTokenServices(getTokenServices()); // changed
		bean.setTokenStore(getTokenStore());
		bean.setRequestFactory(getOAuth2RequestFactory());
		return bean;
	}
	
	@Bean
	public OAuth2RequestFactory getOAuth2RequestFactory() throws PropertyVetoException {
		return new DefaultOAuth2RequestFactory(getClientDetails());
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
	public ResourceBundleMessageSource getMessageSource() {
		ResourceBundleMessageSource bean = new ResourceBundleMessageSource();
		bean.setBasename("resources/internal");
		return bean;
	}
	
	@Bean
	public AuthorityHandlerContainer getAuthorityHandlerContainer() {
		Map<String, AuthorityHandler> map = Maps.newTreeMap();
		
		GoogleAuthorityHandler gh = new GoogleAuthorityHandler(env.getProperty("google.clientIds"));
		map.put("googlelocal", gh);
		FBAuthorityHandler fh = new FBAuthorityHandler();
		map.put("facebooklocal", fh);
		AnonymousAuthorityHandler ah = new AnonymousAuthorityHandler();
		map.put("anonymous", ah);
		
		AuthorityHandlerContainer bean = new AuthorityHandlerContainer(map);
		
		return bean;
	}
	
	@Bean
	public ComboPooledDataSource getDataSource() throws PropertyVetoException {
		ComboPooledDataSource bean = new ComboPooledDataSource();
		
		bean.setDriverClass(env.getProperty("jdbc.driver"));
		bean.setJdbcUrl(env.getProperty("jdbc.url"));
		bean.setUser(env.getProperty("jdbc.user"));
		bean.setPassword(env.getProperty("jdbc.password"));
		bean.setAcquireIncrement(5);
		bean.setIdleConnectionTestPeriod(60);
		bean.setMaxPoolSize(100);
		bean.setMaxStatements(50);
		bean.setMinPoolSize(10);
		
		return bean;
	}

	@Bean(name="entityManagerFactory")
	public LocalContainerEntityManagerFactoryBean getEntityManagerFactoryBean() throws PropertyVetoException {
		LocalContainerEntityManagerFactoryBean bean = new LocalContainerEntityManagerFactoryBean();
//		bean.setPersistenceXmlLocation("classpath:./META-INF/persistence.xml");
		bean.setPersistenceUnitName("permission.provider");
		bean.setDataSource(getDataSource());
		
		HibernateJpaVendorAdapter adapter = new HibernateJpaVendorAdapter();
		adapter.setDatabasePlatform(env.getProperty("jdbc.dialect"));
		adapter.setShowSql(true);
		adapter.setGenerateDdl(true);
		
		bean.setJpaVendorAdapter(adapter);
		bean.setJpaDialect(new IsolationSupportHibernateJpaDialect());
		
		Properties props = new Properties();
		props.setProperty("hibernate.hbm2ddl.auto", "update");
		bean.setJpaProperties(props);

//		bean.setPersistenceProviderClass(HibernatePersistenceProvider.class);
//		bean.setPackagesToScan(ENTITYMANAGER_PACKAGES_TO_SCAN); 
		
		return bean;
	}
	
	
//	@Bean(name="entityManager")
//	public EntityManager getEntityManager() throws PropertyVetoException {
//		EntityManager emb = getEntityManagerFactoryBean().getObject().createEntityManager();
//		return emb;
//	}
	
	
	
//	@Bean(name="entityManagerFactory")
//	public EntityManagerFactory getEntityManagerFactory() throws PropertyVetoException {
//		return getEntityManagerFactoryBean().getNativeEntityManagerFactory();
//	}

	@Bean(name="transactionManager")
	public JpaTransactionManager getTransactionManager() throws PropertyVetoException {
		JpaTransactionManager bean = new JpaTransactionManager();
//		bean.setEntityManagerFactory(getEntityManagerFactoryBean().getNativeEntityManagerFactory()); // ???
		bean.setEntityManagerFactory(getEntityManagerFactoryBean().getObject()); // ???
		return bean;
	}	
	
	
//	@Bean
//	public AuthorizationEndpoint getAuthorizationEndpoint() {
//		AuthorizationEndpoint bean = new AuthorizationEndpoint();
//		bean.setTokenGranter(null);
//		return bean;
//	}
	
	@Bean
	public InternalPasswordEncoder getInternalPasswordEncoder() {
		return new InternalPasswordEncoder();
	}

	@Bean(name = "cookieCleaner")
	public CookieCleaner getCookieCleaner() {
		return new CookieCleaner("JSESSIONID,open_id_session_id,_shibsession", "/dev");
	}

	@Bean(name = "adminCookieCleaner")
	public CookieCleaner getAdminCookieCleaner() {
		return new CookieCleaner("JSESSIONID,open_id_session_id,_shibsession", "/admin");
	}

	@Bean
	public DefaultAuthorityHandler getDefaultHandler() {
		return new DefaultAuthorityHandler(Boolean.parseBoolean(env.getProperty("modeTesting")));
	}

	@Bean(name = "socialEngine")
	public SocialEngine getSocialEngine() throws ClassNotFoundException, InstantiationException, IllegalAccessException {
		return (SocialEngine)Class.forName(env.getProperty("social.engine.impl")).newInstance();
	}

	@Bean
	public CookieLocaleResolver getLocaleResolver() {
		CookieLocaleResolver bean = new CookieLocaleResolver();
		bean.setDefaultLocale(Locale.ITALY);
		return bean;
	}	
	
	
}
