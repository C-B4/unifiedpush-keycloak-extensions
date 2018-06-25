package com.cb4.keycloak.authentication;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.keycloak.services.validation.Validation;

public class CB4PhonValidationTests {

	@Test
	public void testPhones() { 
		List<String> phoneNumbers = new ArrayList<>();
		phoneNumbers.add("+1 1234567890123");
		phoneNumbers.add("+12 123456789");
		phoneNumbers.add("+123 123456");
		phoneNumbers.add("+972 509886532");
		phoneNumbers.add("+1 500 9886532");
		phoneNumbers.add("+972-509886532");
		phoneNumbers.add("+972509886532");
		phoneNumbers.add("972509886532");

		for (String phone : phoneNumbers) {
			assertTrue("Not a valid phone", Validation.isPhoneValid(phone));
		}
		
		List<String> wrongNumbers = new ArrayList<>();
		wrongNumbers.add("++972509886532");
		wrongNumbers.add("+(972) 509886532");
		wrongNumbers.add("+(1) 509886532");
		wrongNumbers.add("+(1) 50 9886532");
		
		for (String phone : wrongNumbers) {
			assertFalse("Valid phone number", Validation.isPhoneValid(phone));
		}
	}
}
