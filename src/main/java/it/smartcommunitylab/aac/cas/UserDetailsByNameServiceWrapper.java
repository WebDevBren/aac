/*******************************************************************************
 * Copyright 2015 Fondazione Bruno Kessler
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 ******************************************************************************/

package it.smartcommunitylab.aac.cas;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * @author raman
 *
 */
public class UserDetailsByNameServiceWrapper <T extends Authentication> implements AuthenticationUserDetailsService<T>, InitializingBean {

    /**
     * Constructs an empty wrapper for compatibility with Spring Security 2.0.x's method of using a setter.
     */
    public UserDetailsByNameServiceWrapper() {
        // constructor for backwards compatibility with 2.0
    }

    /**
     * Get the UserDetails object from the wrapped UserDetailsService
     * implementation
     */
    public UserDetails loadUserDetails(T authentication) throws UsernameNotFoundException {
        return createByUsername(authentication.getName());
    }
	/**
	 * @param name
	 * @return
	 */
	private UserDetails createByUsername(String name) {
		return new WrappedUserDetails(name);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
	}

	public static class WrappedUserDetails implements UserDetails {
		private static final long serialVersionUID = -648448028156537611L;

		private static final List<GrantedAuthority> list = Collections.<GrantedAuthority>singletonList(new SimpleGrantedAuthority("ROLE_USER"));

		private String user; 

		public WrappedUserDetails(String user) {
			super();
			this.user = user;
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return list;
		}

		@Override
		public String getPassword() {
			return user;
		}

		@Override
		public String getUsername() {
			return user;
		}

		@Override
		public boolean isAccountNonExpired() {
			return true;
		}

		@Override
		public boolean isAccountNonLocked() {
			return true;
		}

		@Override
		public boolean isCredentialsNonExpired() {
			return true;
		}

		@Override
		public boolean isEnabled() {
			return true;
		}
		
	}
	
}
