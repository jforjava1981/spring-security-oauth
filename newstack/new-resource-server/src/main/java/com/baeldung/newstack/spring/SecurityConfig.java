package com.baeldung.newstack.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties("spring.security.oauth2.resourceserver.jwt")
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private String issuerUri;

    @Override
    protected void configure(HttpSecurity http) throws Exception {// @formatter:off
        http.authorizeRequests()
                .antMatchers(HttpMethod.GET, "/api/projects/**")
                .hasAuthority("SCOPE_read")
                .antMatchers(HttpMethod.GET, "/user/info")
                .hasAuthority("SCOPE_superuser")
                .antMatchers(HttpMethod.POST, "/api/projects")
                .hasAuthority("SCOPE_write")
                .anyRequest()
                .authenticated()
                .and()
                .oauth2ResourceServer().jwt().jwtAuthenticationConverter(grantedAuthoritiesExtractor());
    }//@formatter:on

    private Converter<Jwt, AbstractAuthenticationToken> grantedAuthoritiesExtractor() {
        JwtAuthenticationConverter jwtAuthenticationConverter =
                new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter
                (new GrantedAuthoritiesExtractor());
        return jwtAuthenticationConverter;
    }

    //@Bean
    JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(issuerUri);

        OAuth2TokenValidator<Jwt> preferredUserNameClaimVerifier = new PreferredUserNameClaimValidator();
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> withPreferredUserNameValidator = new DelegatingOAuth2TokenValidator<>(withIssuer, preferredUserNameClaimVerifier);

        jwtDecoder.setJwtValidator(withPreferredUserNameValidator);

        return jwtDecoder;
    }

    public void setIssuerUri(String issuerUri) {
        this.issuerUri = issuerUri;
    }


    private static class GrantedAuthoritiesExtractor implements Converter<Jwt, Collection<GrantedAuthority>> {
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            String scopes = (String)
                    jwt.getClaims().get("scope");
            String userName = (String)jwt.getClaims().get("preferred_username");
            if(userName.endsWith("@baeldung.com")) {
                scopes = scopes + " " + "superuser";
            }
            List<String> authorities =  Arrays.asList(scopes.split(" "));
            return authorities.stream()
                    .map(authority -> "SCOPE_" + authority )
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }
    }
}