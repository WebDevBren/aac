package it.smartcommunitylab.aac.auth.fb;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.filter.OncePerRequestFilter;

public class FBFilter extends OncePerRequestFilter {

	@Value("${application.url}")
	private String applicationURL;

	@Value("${mode.testing}")
	private boolean testMode;

	@Override
	public void destroy() {
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String loggedWithFB = (String) request.getSession().getAttribute(
				FBAuthHelper.SESSION_FB_CHECK);
		if (loggedWithFB == null && !testMode) {
			response.sendRedirect(applicationURL + "/auth/fb-oauth");
		} else {
			filterChain.doFilter(request, response);
		}

	}

}
