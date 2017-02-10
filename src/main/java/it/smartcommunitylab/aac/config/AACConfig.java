package it.smartcommunitylab.aac.config;

import it.smartcommunitylab.aac.authority.AnonymousAuthorityHandler;
import it.smartcommunitylab.aac.authority.AuthorityHandler;
import it.smartcommunitylab.aac.authority.AuthorityHandlerContainer;
import it.smartcommunitylab.aac.authority.DefaultAuthorityHandler;
import it.smartcommunitylab.aac.authority.FBAuthorityHandler;
import it.smartcommunitylab.aac.authority.GoogleAuthorityHandler;
import it.smartcommunitylab.aac.model.ClientDetailsRowMapper;
import it.smartcommunitylab.aac.oauth.AutoJdbcAuthorizationCodeServices;
import it.smartcommunitylab.aac.oauth.AutoJdbcTokenStore;
import it.smartcommunitylab.aac.oauth.CachedResourceStorage;
import it.smartcommunitylab.aac.oauth.ClientCredentialsFilter;
import it.smartcommunitylab.aac.oauth.IsolationSupportHibernateJpaDialect;
import it.smartcommunitylab.aac.oauth.NonRemovingTokenServices;
import it.smartcommunitylab.aac.oauth.UserApprovalHandler;
import it.smartcommunitylab.aac.oauth.UserDetailsRepo;

import java.beans.PropertyVetoException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
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
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.view.ContentNegotiatingViewResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import com.google.api.client.util.Lists;
import com.google.common.collect.Maps;
import com.mchange.v2.c3p0.ComboPooledDataSource;

import eu.trentorise.smartcampus.resourceprovider.filter.ResourceAuthenticationManager;
import eu.trentorise.smartcampus.resourceprovider.jdbc.JdbcServices;
//import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;

@Configuration 
@ComponentScan//("it.smartcommunitylab.aac")
@EntityScan({"it.smartcommunitylab.aac.model", "it.smartcommunitylab.aac.profile.model"})
@EnableWebMvc
@ComponentScan("it.smartcommunitylab.aac")
@PropertySource("classpath:commoncore.properties")
@EnableTransactionManagement
@EnableAutoConfiguration
@EnableJpaRepositories(basePackages = {"it.smartcommunitylab.aac.repository"}, queryLookupStrategy = QueryLookupStrategy.Key.CREATE)
public class AACConfig extends WebMvcConfigurerAdapter {

	private static final String[] CLASSPATH_RESOURCE_LOCATIONS = {
		"classpath:/META-INF/resources/", "classpath:/resources/",
		"classpath:/static/", "classpath:/public/" };		
	
	@Autowired
	private Environment env;
	
//	@Bean
//	public TemplateEngine getTemplateEngine() {
//		TemplateEngine bean = new TemplateEngine();
//		ClassLoaderTemplateResolver tr = new ClassLoaderTemplateResolver(); 
//		tr.setPrefix("/templates/");
//		tr.setSuffix(".html");
//		tr.setCharacterEncoding("UTF-8");
//		tr.setTemplateMode("HTML5");
//		bean.setTemplateResolver(tr);
//		return bean;
//	}
	
	@Bean
	public ClientCredentialsFilter getClientCredentialsFilter() throws PropertyVetoException {
		ClientCredentialsFilter ccf = new ClientCredentialsFilter("/internal/register/rest");
		ccf.setAuthenticationManager(getResourceAuthenticationManager());
		return ccf;
	}	

	@Bean
	public UserDetailsRepo getUserDetailsService() {
		return new UserDetailsRepo();
	}
	
	@Bean
	public AuthenticationManager getResourceAuthenticationManager() throws PropertyVetoException {
		ResourceAuthenticationManager bean = new ResourceAuthenticationManager();
		bean.setTokenStore(getTokenStore());
		bean.setAuthServices(getJdbcServices());
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
		bean.setTokenStore(getTokenStore());
		bean.setRequestFactory(getOAuth2RequestFactory());
		return bean;
	}
	
	@Bean
	public OAuth2RequestFactory getOAuth2RequestFactory() throws PropertyVetoException {
		return new DefaultOAuth2RequestFactory(getClientDetails());
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
	
//	@Bean(name = "cookieCleaner")
//	public CookieCleaner getCookieCleaner() {
//		return new CookieCleaner("JSESSIONID,open_id_session_id,_shibsession", "/dev");
//	}
//
//	@Bean(name = "adminCookieCleaner")
//	public CookieCleaner getAdminCookieCleaner() {
//		return new CookieCleaner("JSESSIONID,open_id_session_id,_shibsession", "/admin");
//	}

	@Bean
	public DefaultAuthorityHandler getDefaultHandler() {
		return new DefaultAuthorityHandler(Boolean.parseBoolean(env.getProperty("modeTesting")));
	}

//	@Bean(name = "socialEngine")
//	public SocialEngine getSocialEngine() throws ClassNotFoundException, InstantiationException, IllegalAccessException {
//		return (SocialEngine)Class.forName(env.getProperty("social.engine.impl")).newInstance();
//	}

	@Bean
	public CookieLocaleResolver getLocaleResolver() {
		CookieLocaleResolver bean = new CookieLocaleResolver();
		bean.setDefaultLocale(Locale.ITALY);
		return bean;
	}	
	
    @Override
    public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
        configurer.enable();
    }	
	
//    @Bean
//    public ContentNegotiationManager getContentNegotiationManager() {
//    	ContentNegotiationManager bean = new ContentNegotiationManager();
//    	
//    	bean.
//    }
    
    @Bean
    public ViewResolver viewResolver() {
    	ContentNegotiatingViewResolver bean = new ContentNegotiatingViewResolver();
 
    	InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setViewClass(JstlView.class);
        viewResolver.setPrefix("/WEB-INF/jsp/");
        viewResolver.setSuffix(".jsp");
 
        List<ViewResolver> viewResolvers = Lists.newArrayList();
        viewResolvers.add(viewResolver);
        bean.setViewResolvers(viewResolvers);
        
        List<View> views = Lists.newArrayList();
        MappingJackson2JsonView view = new MappingJackson2JsonView();
        views.add(view);        
        bean.setDefaultViews(views);
        
        return bean;
    }	
	
	 @Override
	 public void addResourceHandlers(ResourceHandlerRegistry registry) {
		 registry.addResourceHandler("/**").addResourceLocations(CLASSPATH_RESOURCE_LOCATIONS);		 
	 }
	 
	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/**").allowedMethods("PUT", "DELETE", "GET", "POST").allowedOrigins("*");
	}	
	
	
}
