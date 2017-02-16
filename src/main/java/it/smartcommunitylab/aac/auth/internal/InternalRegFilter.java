package it.smartcommunitylab.aac.auth.internal;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

public class InternalRegFilter extends OncePerRequestFilter {

	private String applicationURL;

	private boolean testMode;

	public static final String SESSION_INTERNAL_CHECK = "internal-login"; 
	
	public InternalRegFilter(String applicationURL, boolean testMode) {
		super();
		this.applicationURL = applicationURL;
		this.testMode = testMode;
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
		if (loggedWithInternal == null && !testMode) {
			response.sendRedirect(applicationURL + "/internal/login");
		} else {
			filterChain.doFilter(request, response);
		}

	}

}
