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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.util.EntityUtils;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidationException;

/**
 * @author raman
 *
 */
public class NoSSLCas20ServiceTicketValidator extends Cas20ServiceTicketValidator {

	/**
	 * @param casServerUrlPrefix
	 */
	public NoSSLCas20ServiceTicketValidator(String casServerUrlPrefix) {
		super(casServerUrlPrefix);
	}

	@Override
	public Assertion validate(String ticket, String service)
			throws TicketValidationException {
        final String validationUrl = constructValidationUrl(ticket, service);
        if (log.isDebugEnabled()) {
            log.debug("Constructing validation url: " + validationUrl);
        }

        try {
        	log.debug("Retrieving response from server.");
            final String serverResponse = retrieveResponseFromServerNoSSL(new URL(validationUrl), ticket);

            if (serverResponse == null) {
                throw new TicketValidationException("The CAS server returned no response.");
            }
            
            if (log.isDebugEnabled()) {
            	log.debug("Server response: " + serverResponse);
            }

            return parseResponseFromServer(serverResponse);
        } catch (final MalformedURLException e) {
            throw new TicketValidationException(e);
        }	}

	/**
	 * @param url
	 * @param ticket
	 * @return
	 */
	private String retrieveResponseFromServerNoSSL(URL url, String ticket) {
        try {
			final HttpGet get = new HttpGet(url.toString());
			final HttpResponse resp = getHttpClient().execute(get);
			String response = EntityUtils.toString(resp.getEntity(),"UTF-8");
			return response;
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
	}


	private static HttpClient getAcceptAllHttpClient(HttpParams inParams) {
		HttpClient client = null;

		HttpParams params = inParams != null ? inParams : new BasicHttpParams();

		try {
			KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
			trustStore.load(null, null);

			SchemeRegistry registry = new SchemeRegistry();
			registry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80));

			// IMPORTANT: use CustolSSLSocketFactory for 2.2
			SSLSocketFactory sslSocketFactory = new CustomSSLSocketFactory(trustStore);
			sslSocketFactory.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
			registry.register(new Scheme("https", sslSocketFactory, 443));

			ClientConnectionManager ccm = new ThreadSafeClientConnManager(params, registry);

			client = new DefaultHttpClient(ccm, params);
		} catch (Exception e) {
			client = new DefaultHttpClient(params);
		}

		return client;
	}
	
	private static class CustomSSLSocketFactory extends SSLSocketFactory {
		SSLContext sslContext = SSLContext.getInstance("TLS");

		public CustomSSLSocketFactory(KeyStore truststore) throws NoSuchAlgorithmException, KeyManagementException,
				KeyStoreException, UnrecoverableKeyException {
			super(truststore);

			TrustManager tm = new X509TrustManager() {
				public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				}

				public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				}

				public X509Certificate[] getAcceptedIssuers() {
					return null;
				}
			};

			sslContext.init(null, new TrustManager[] { tm }, null);
		}

		@Override
		public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException,
				UnknownHostException {
			return sslContext.getSocketFactory().createSocket(socket, host, port, autoClose);
		}

		@Override
		public Socket createSocket() throws IOException {
			return sslContext.getSocketFactory().createSocket();
		}
	}
	
	protected static HttpClient getHttpClient() {
		HttpClient httpClient = getAcceptAllHttpClient(null);
		return httpClient;
	}
}
