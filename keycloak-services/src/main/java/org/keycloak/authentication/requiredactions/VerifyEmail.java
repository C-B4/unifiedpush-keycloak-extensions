/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.authentication.requiredactions;

import java.net.URI;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status.Family;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriBuilderException;
import javax.ws.rs.core.UriInfo;

import org.jboss.logging.Logger;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.actiontoken.verifyemail.VerifyEmailActionToken;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserModel.RequiredAction;
import org.keycloak.services.Urls;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class VerifyEmail implements RequiredActionProvider, RequiredActionFactory {
	private static final Logger logger = Logger.getLogger(VerifyEmail.class);

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		
		if (context.getRealm().isVerifyEmail() && !context.getUser().isEmailVerified()) {
			context.getUser().addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
			logger.debug("User is required to verify email");
		}
		
		// If no password, require password validation  
        if (isBlank(formData.getFirst(RegistrationPage.FIELD_PASSWORD))) {
        	context.getUser().addRequiredAction(RequiredAction.UPDATE_PASSWORD.name());
        }
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();

		if (context.getUser().isEmailVerified()) {
			context.success();
			authSession.removeAuthNote(Constants.VERIFY_EMAIL_KEY);
			return;
		}

		String email = context.getUser().getEmail();
		if (Validation.isBlank(email)) {
			// Extract username as email
			email = context.getUser().getUsername();
		}

		if (Validation.isBlank(email)) {
			context.ignore();
			return;
		}

		LoginFormsProvider loginFormsProvider = context.form();
		Response challenge;

		// Do not allow resending e-mail by simple page refresh, i.e. when e-mail sent,
		// it should be resent properly via email-verification endpoint
		if (!Objects.equals(authSession.getAuthNote(Constants.VERIFY_EMAIL_KEY), email)) {
			authSession.setAuthNote(Constants.VERIFY_EMAIL_KEY, email);
			EventBuilder event = context.getEvent().clone().event(EventType.SEND_VERIFY_EMAIL).detail(Details.EMAIL,
					email);
			challenge = sendVerifyEmail(context, context.getSession(), loginFormsProvider, context.getUser(),
					context.getAuthenticationSession(), event);
		} else {
			challenge = loginFormsProvider.createResponse(UserModel.RequiredAction.VERIFY_EMAIL);
		}

		context.challenge(challenge);
	}

	@Override
	public void processAction(RequiredActionContext context) {
		logger.debugf("Re-sending email requested for user: %s", context.getUser().getUsername());

		// This will allow user to re-send email again
		context.getAuthenticationSession().removeAuthNote(Constants.VERIFY_EMAIL_KEY);

		requiredActionChallenge(context);
	}

	@Override
	public void close() {

	}

	@Override
	public RequiredActionProvider create(KeycloakSession session) {
		return this;
	}

	@Override
	public void init(Config.Scope config) {

	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {

	}

	@Override
	public String getDisplayText() {
		return "Verify Email";
	}

	@Override
	public String getId() {
		return UserModel.RequiredAction.VERIFY_EMAIL.name();
	}

	private Response sendVerifyEmail(RequiredActionContext context, KeycloakSession session, LoginFormsProvider forms, UserModel user, AuthenticationSessionModel authSession, EventBuilder event) throws UriBuilderException, IllegalArgumentException {
    	
        RealmModel realm = session.getContext().getRealm();
        UriInfo uriInfo = session.getContext().getUri();
        
        int validityInSecs = realm.getActionTokenGeneratedByUserLifespan(VerifyEmailActionToken.TOKEN_TYPE);
        int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;

        String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId();
        VerifyEmailActionToken token = new VerifyEmailActionToken(user.getId(), absoluteExpirationInSecs, authSessionEncodedId, user.getEmail());
        String sToken = token.serialize(session, realm, uriInfo);
        UriBuilder builder = Urls.actionTokenBuilder(uriInfo.getBaseUri(), sToken, authSession.getClient().getClientId(), authSession.getTabId());
        
        String link = builder.build(realm.getName()).toString();
        long expirationInMinutes = TimeUnit.SECONDS.toMinutes(validityInSecs);
        
		if (Validation.isPhoneValid(user.getUsername())) {
			return sendSMS(realm, session, forms, user, authSession, event, link, expirationInMinutes);
		}

        return sendEmail(realm, session, forms, user, authSession, event, link, expirationInMinutes);
    }
	
	private Response sendSMS(RealmModel realm, KeycloakSession session, LoginFormsProvider forms,
			UserModel user, AuthenticationSessionModel authSession, EventBuilder event, String link,
			long expirationInMinutes) {
		logger.trace("sending sms message verifications");
		
		ResteasyClient client = new ResteasyClientBuilder().build();
		URI requestUri = session.getContext().getUri().getRequestUri();
		String serverURL = requestUri.getScheme() + "://" + requestUri.getHost() + "/unifiedpush-server/rest";
		// First register installation
		try {
			ResteasyWebTarget target = client.target(serverURL + "/shortlinks/type/link/username/" + user.getUsername());
			Response response = target.request().put(Entity.entity(link, MediaType.TEXT_PLAIN));
			if (Family.familyOf(response.getStatus()) != Family.SUCCESSFUL)
				throw new Exception("Unable to register new shortlink code. response code " + response.getStatus()); 
			
			String code = response.readEntity(String.class);
			response.close();
			
			target = client.target(serverURL + "/shortlinks/sms/" + user.getUsername());
			response = target.request().put(Entity.entity(code, MediaType.TEXT_PLAIN));
			if (Family.familyOf(response.getStatus()) != Family.SUCCESSFUL)
				throw new Exception("Unable to send SMS shortlink code. response code " + response.getStatus()); 
			response.close();
			
			event.success();
		}catch (Exception e) {
			logger.error("Failed to send verification sms", e);
			event.error(Errors.EMAIL_SEND_FAILED);
		}
		
		return forms.createResponse(UserModel.RequiredAction.VERIFY_EMAIL);
	}
			
	private Response sendEmail(RealmModel realm, KeycloakSession session, LoginFormsProvider forms,
			UserModel user, AuthenticationSessionModel authSession, EventBuilder event, String link,
			long expirationInMinutes)
			throws UriBuilderException, IllegalArgumentException {

		try {
			session.getProvider(EmailTemplateProvider.class).setAuthenticationSession(authSession).setRealm(realm)
					.setUser(user).sendVerifyEmail(link, expirationInMinutes);
			event.success();
		} catch (EmailException e) {
			logger.error("Failed to send verification email", e);
			event.error(Errors.EMAIL_SEND_FAILED);
		}

		return forms.createResponse(UserModel.RequiredAction.VERIFY_EMAIL);
	}

    /**
     * Check if string is blank (null or lenght is 0 or contains only white characters)
     * 
     * @param s to check
     * @return true if string is blank
     */
    public static boolean isBlank(String s) {
        return s == null || s.trim().length() == 0;
    }
}
