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

package org.keycloak.authentication.forms;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class RegistrationProfile implements FormAction, FormActionFactory {
	private static final Logger logger = Logger.getLogger(RegistrationProfile.class);

	public static final String PROVIDER_ID = "registration-profile-action";
	public static final String MISSING_CLIENT_ID = "missingClientIDMessage";
	public static final String INVALID_PHONE = "invalidPhoneMessage";

	@Override
	public String getHelpText() {
		return "Validates email, first name, and last name attributes and stores them in user data.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return null;
	}

	@Override
	public void validate(ValidationContext context) {
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		List<FormMessage> errors = new ArrayList<>();

		formData.forEach((k, v) -> {
			logger.warn("Key: " + k + " Value: " + v);
		});

		context.getEvent().detail(Details.REGISTER_METHOD, "form");
		String eventError = Errors.INVALID_REGISTRATION;
		
		String username = formData.getFirst(Validation.FIELD_USERNAME);
		String clientId = formData.getFirst(Validation.FIELD_CLIENT_ID);
		String deviceType = formData.getFirst(Validation.FIELD_IS_MOBILE);
		
		boolean isMobile = true;
		boolean usernameValid = true;

		if (Validation.isBlank(clientId)) {
			errors.add(new FormMessage(Validation.FIELD_CLIENT_ID, MISSING_CLIENT_ID));
		}

		if (Validation.isBlank(username)) {
			errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, Messages.MISSING_USERNAME));
			usernameValid = false;
		}

		if (!Validation.isBlank(username)) {
			switch (deviceType.toUpperCase()) {
			case "WEBAPP":
				isMobile = false;
				logger.warn(username);
	
				if (Validation.isEmailValid(username)) {
					formData.add(Validation.FIELD_EMAIL, username);
				} else {
					usernameValid = false;
					logger.debug("invalid email format: " + username);
					errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, Messages.INVALID_EMAIL));
				}
				break;
			case "MOBILE":
				isMobile = true;
				if (!Validation.isPhoneValid(username)) {
					usernameValid = false;
					logger.debug("invalid phone format: " + username);
					errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, INVALID_PHONE));
				}
				break;
			default:
				usernameValid = false;
				logger.debug("unsupported application type: " + deviceType);
				errors.add(new FormMessage(Validation.FIELD_IS_MOBILE, Messages.INVALID_PARAMETER));
				break;
			}
		}
		
		if (!isMobile && usernameValid && !context.getRealm().isDuplicateEmailsAllowed()
				&& context.getSession().users().getUserByEmail(username, context.getRealm()) != null) {
			eventError = Errors.EMAIL_IN_USE;
			formData.remove(Validation.FIELD_EMAIL);
			context.getEvent().detail(Details.EMAIL, username);
			errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, Messages.EMAIL_EXISTS));
		}

		// Validate duplicated phones
		if (isMobile && usernameValid && !context.getRealm().isDuplicateEmailsAllowed()
				&& context.getSession().users().getUserByUsername(username, context.getRealm()) != null) {
			eventError = Errors.USERNAME_IN_USE;
			formData.remove(Validation.FIELD_EMAIL);
			context.getEvent().detail(Details.EMAIL, username);
			errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, INVALID_PHONE));
		}

		if (errors.size() > 0) {
			context.error(eventError);
			context.validationError(formData, errors);
			return;
		} else {
			context.success();
		}
	}

	@Override
	public void success(FormContext context) {
		UserModel user = context.getUser();
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		user.setFirstName(formData.getFirst(RegistrationPage.FIELD_FIRST_NAME));
		user.setLastName(formData.getFirst(RegistrationPage.FIELD_LAST_NAME));
		user.setEmail(formData.getFirst(RegistrationPage.FIELD_EMAIL));

		// Add client roles to user
		String clientId = formData.getFirst(Validation.FIELD_CLIENT_ID);
		if (!Validation.isBlank(clientId)) {
			ClientModel clientModel = context.getRealm().getClientById(clientId);
			if (clientModel != null) {
				Set<RoleModel> roles = clientModel.getRoles();
				user.getClientRoleMappings(clientModel).addAll(roles);
			} else {
				logger.debug("client roles are empty or null: " + clientId);
			}
		} else {
			logger.warn("Unknown clientid, user will not be assigned to client roles");
		}
	}

	@Override
	public void buildPage(FormContext context, LoginFormsProvider form) {
		// complete
	}

	@Override
	public boolean requiresUser() {
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

	}

	@Override
	public boolean isUserSetupAllowed() {
		return false;
	}

	@Override
	public void close() {

	}

	@Override
	public String getDisplayType() {
		return "Profile Validation";
	}

	@Override
	public String getReferenceCategory() {
		return null;
	}

	@Override
	public boolean isConfigurable() {
		return false;
	}

	private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
			AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED };

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public FormAction create(KeycloakSession session) {
		return this;
	}

	@Override
	public void init(Config.Scope config) {

	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {

	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}
}
