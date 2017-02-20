package it.smartcommunitylab.aac.auth.internal;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public class InternalRegFilter extends OncePerRequestFilter {

	public static final String SESSION_INTERNAL_CHECK = "internal-login"; 
	
	private RequestMatcher matcher = null;

	@Value("${application.url}")
	private String appUrl;
	
	public InternalRegFilter(String filterProcessesUrl) {
		super();
		this.matcher = new AntPathRequestMatcher(filterProcessesUrl);;
	}

	@Override
	public void destroy() {
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String loggedWithInternal = (String) request.getSession().getAttribute(
				InternalRegFilter.SESSION_INTERNAL_CHECK);
		if (loggedWithInternal == null) {
			response.sendRedirect(appUrl + "/internal/login");
		} else {
			filterChain.doFilter(request, response);
		}

	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		return !matcher.matches(request);
	}

	
}
