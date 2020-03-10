package com.baeldung.newstack.spring;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class PreferredUserNameClaimValidator implements OAuth2TokenValidator<Jwt> {
    OAuth2Error error = new OAuth2Error("invalid_token", "\"user_name claim is invalid\"", null);

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String username = (String) jwt.getClaims().get("preferred_username");
        if ((username == null) || (username.length() == 0) || !username.endsWith("@baeldung.com")) {
            return OAuth2TokenValidatorResult.failure(error);
        }
        return OAuth2TokenValidatorResult.success();
    }
}
