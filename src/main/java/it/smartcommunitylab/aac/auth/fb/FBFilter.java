package it.smartcommunitylab.aac.auth.fb;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

public class FBFilter extends OncePerRequestFilter {

	private String applicationURL;

	private boolean testMode;
	
	public FBFilter(String applicationURL, boolean testMode) {
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

		System.err.println("FB");
		
		String loggedWithFB = (String) request.getSession().getAttribute(
				FBAuthHelper.SESSION_FB_CHECK);
		if (loggedWithFB == null && !testMode) {
			response.sendRedirect(applicationURL + "/auth/fb-oauth");
		} else {
			filterChain.doFilter(request, response);
		}

	}

}
