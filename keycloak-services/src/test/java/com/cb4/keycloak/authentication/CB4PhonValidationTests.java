package com.cb4.keycloak.authentication;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.junit.Test;
import org.keycloak.services.validation.Validation;

public class CB4PhonValidationTests {

	@Test
	public void testPhones() {
		Pattern pattern = Validation.PHONE_PATTERN;

		List<String> phoneNumbers = new ArrayList<>();
		phoneNumbers.add("+1 1234567890123");
		phoneNumbers.add("+12 123456789");
		phoneNumbers.add("+123 123456");

		for (String phone : phoneNumbers) {
			assertTrue("Not a valid phone", pattern.matcher(phone).matches());
		}

	}
}
