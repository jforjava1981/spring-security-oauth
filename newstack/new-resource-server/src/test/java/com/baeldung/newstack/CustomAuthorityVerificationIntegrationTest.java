package com.baeldung.newstack;

import io.restassured.http.ContentType;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.net.URI;
import java.net.URISyntaxException;

import static io.restassured.RestAssured.given;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {NewResourceServerApp.class}, webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class CustomAuthorityVerificationIntegrationTest {


    private static final String CLIENT_ID = "newClient";

    private static final String CLIENT_SECRET = "newClientSecret";

    private static final String clientAuthUrl = "http://localhost:8083/auth/realms/baeldung/protocol/openid-connect/auth";


    private static final String tokenEndpoint = "http://localhost:8083/auth/realms/baeldung/protocol/openid-connect/token";

    private static final String resourceServerUrl = "http://localhost:8081/new-resource-server/user/info";

    private static final String SESSION_COOKIE = "AUTH_SESSION_ID";

    private String getToken(String userName, String password) throws URISyntaxException {

        Response response =
                given().
                        param("response_type", "code")
                        .param("client_id", CLIENT_ID)
                        .param("scope", "read", "write")
                        .param("redirect_uri", "http://localhost:8082/new-client/login/oauth2/code/custom")
                        .when().
                        get(clientAuthUrl)
                        .andReturn();
        String sessionCookieValue = response.getCookie(SESSION_COOKIE);
        String credentialFormHTML = response.asString();
        XmlPath xmlPath = new XmlPath(XmlPath.CompatibilityMode.HTML, credentialFormHTML);
        xmlPath.setRoot("html");
        String formActionUrl = xmlPath.get("body.div.div[1].div.div.div.div.form.@action");

        String redirectionUrl = given()
                .when().redirects().follow(false)
                .formParam("username",userName)
                .formParam("password", password)
                .cookie(SESSION_COOKIE,sessionCookieValue)
                .accept(ContentType.fromContentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
                .post(formActionUrl)
                .andReturn().getHeader("location");
        URI redirectionURI =  new URI(redirectionUrl);
        String queryString = redirectionURI.getQuery();
        String authCode = "";
        if(queryString.indexOf("&",queryString.indexOf("code=")) == -1) {
            authCode = queryString.substring(queryString.indexOf("code=") + 5);
        } else {
            authCode = queryString.substring(queryString.indexOf("code=") + 5, queryString.indexOf("&",queryString.indexOf("code=")));
        }

        String sesstionState = "";
        if(queryString.indexOf("&",queryString.indexOf("session_state=")) == -1) {
            sesstionState = queryString.substring(queryString.indexOf("session_state=") + 14);
        } else {
            sesstionState = queryString.substring(queryString.indexOf("session_state=") + 14, queryString.indexOf("&",queryString.indexOf("session_state=") ));
        }

        String token =
                given().
                        param("grant_type", "authorization_code")
                        .param("code", authCode)
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", CLIENT_SECRET)
                        .param("scope","read,write")
                        .param("state",sesstionState)
                        .param("redirect_uri", "http://localhost:8082/new-client/login/oauth2/code/custom")
                        .when().
                        post(tokenEndpoint).
                        then().
                        contentType(ContentType.JSON)
                        .statusCode(200).
                        extract().
                        path("access_token");
        return token;
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
    public void whenResourceAccessed_With_UserHavingDomain_other_than_Baeldung_thenUnauthorised() throws URISyntaxException {
        String accessToken = getToken("mike@other.com", "pass");

        given().
                header("Authorization", "Bearer " + accessToken)
                .when()
                .get(resourceServerUrl)
                .then()
                .statusCode(403);
    }

}
