/*******************************************************************************
 * Copyright 2012-2013 Trento RISE
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package it.smartcommunitylab.aac.auth.google;

import org.codehaus.jackson.annotate.JsonProperty;

/**
 * Model for user's info logged by Google.
 * 
 * @author Giulia Canobbio
 * 
 */
public class GoogleUser {

	private String id;

	private String email;

	@JsonProperty(value = "verified_email")
	private boolean verifiedEmail;

	private String name;

	@JsonProperty("given_name")
	private String givenName;

	@JsonProperty(value = "family_name")
	private String familyName;

	private String picture;

	private String locale;

	/**
	 * Get google user id.
	 * 
	 * @return String id
	 */
	public String getId() {
		return id;
	}

	/**
	 * Set google user id.
	 * 
	 * @param id
	 *            : String
	 */
	public void setId(String id) {
		this.id = id;
	}

	/**
	 * Get email address.
	 * 
	 * @return String email
	 */
	public String getEmail() {
		return email;
	}

	/**
	 * Set email address.
	 * 
	 * @param email
	 *            : String
	 */
	public void setEmail(String email) {
		this.email = email;
	}

	/**
	 * Check if email is verified.
	 * 
	 * @return boolean true if email is verified in Google o.w. false
	 */
	public boolean isVerifiedEmail() {
		return verifiedEmail;
	}

	/**
	 * Set email verified value.
	 * 
	 * @param verified_email
	 *            : boolean
	 */
	public void setVerifiedEmail(boolean verifiedEmail) {
		this.verifiedEmail = verifiedEmail;
	}

	/**
	 * Get username.
	 * 
	 * @return String name : username in Google
	 */
	public String getName() {
		return name;
	}

	/**
	 * Set username.
	 * 
	 * @param name
	 *            : String username
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Get first name.
	 * 
	 * @return String first name
	 */
	public String getGivenName() {
		return givenName;
	}

	/**
	 * Set first name.
	 * 
	 * @param givenName
	 *            : String first name
	 */

	public void setGivenName(String givenName) {
		this.givenName = givenName;
	}

	/**
	 * Get surname.
	 * 
	 * @return String family name
	 */
	public String getFamilyName() {
		return familyName;
	}

	/**
	 * Set surname.
	 * 
	 * @param familyName
	 *            : String
	 */
	public void setFamilyName(String familyName) {
		this.familyName = familyName;
	}

	/**
	 * Get image.
	 * 
	 * @return String link to picture
	 */
	public String getPicture() {
		return picture;
	}

	/**
	 * Set image.
	 * 
	 * @param picture
	 *            : String link to picture
	 */
	public void setPicture(String picture) {
		this.picture = picture;
	}

	/**
	 * Get locale.
	 * 
	 * @return String locale
	 */
	public String getLocale() {
		return locale;
	}

	/**
	 * Set locale.
	 * 
	 * @param locale
	 *            : String
	 */
	public void setLocale(String locale) {
		this.locale = locale;
	}

}
