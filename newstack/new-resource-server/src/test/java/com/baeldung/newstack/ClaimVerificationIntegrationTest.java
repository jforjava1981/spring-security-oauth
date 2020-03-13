package com.baeldung.newstack;

import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static io.restassured.RestAssured.given;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {NewResourceServerApp.class}, webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class ClaimVerificationIntegrationTest {

    private static final String CLIENT_ID = "newClient";
    private static final String CLIENT_SECRET = "newClientSecret";

    private static final String tokenEndpoint = "http://localhost:8083/auth/realms/baeldung/protocol/openid-connect/token";

    private static final String resourceServerUrl = "http://localhost:8081/new-resource-server/api/projects";

    private String getToken(String userName, String password) {
        // @formatter:off

        String token =
                given().
                        param("grant_type", "password")
                        .param("client_id", CLIENT_ID)
                        .param("username", userName)
                        .param("password", password)
                        .param("client_secret", CLIENT_SECRET)
                        .when().
                        post(tokenEndpoint).
                        then().
                        contentType(ContentType.JSON)
                        .statusCode(200).
                        extract().
                        path("access_token");


        return token;

        // @formatter:on

    }

    @Test
    public void whenResourceAccessed_With_UserHavingDomain_Baeldungcom_thenSuccess() throws Exception {
        String accessToken = getToken("test@baeldung.com", "test123");

        given().
                header("Authorization", "Bearer " + accessToken)
                .when()
                .get(resourceServerUrl)
                .then()
                .statusCode(200);
    }

    @Test
    public void whenResourceAccessed_With_UserHavingDomain_other_than_Baeldung_thenUnauthorised() {
        String accessToken = getToken("mike@other.com", "pass");

        given().
                header("Authorization", "Bearer " + accessToken)
                .when()
                .get(resourceServerUrl)
                .then()
                .statusCode(401);
    }

}