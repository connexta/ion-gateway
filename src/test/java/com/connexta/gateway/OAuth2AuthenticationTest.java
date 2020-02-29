/*
 * Copyright (c) 2019 Connexta, LLC
 *
 * Released under the GNU Lesser General Public License version 3; see
 * https://www.gnu.org/licenses/lgpl-3.0.html
 */
package com.connexta.gateway;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClient.ResponseSpec;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class OAuth2AuthenticationTest {

  @Autowired private ApplicationContext context;

  @Autowired private WebTestClient webClient;

  @Before
  public void setup() {
    this.webClient =
        WebTestClient.bindToApplicationContext(this.context).apply(springSecurity()).build();
  }

  @Test
  public void testUnauthenticatedRequestBrowserClient() {
    ResponseSpec response =
        webClient
            .get()
            .uri("/service")
            .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
            .exchange();
    response
        .expectStatus()
        .is3xxRedirection()
        .expectHeader()
        .valueEquals("Location", "/oauth2/authorization/keycloak");
  }

  @Test
  public void testUnauthenticatedRequestNonBrowserClient() {
    ResponseSpec response = webClient.get().uri("/service").exchange();
    response.expectStatus().is4xxClientError();
  }

  // TODO: Implement these tests once
  // https://github.com/spring-cloud/spring-cloud-gateway/issues/1491 is fixed
  @Test
  @Ignore
  public void testEmptyWebContextPolicy() {}

  @Test
  @Ignore
  public void testAuthorized() {}

  @Test
  @Ignore
  public void testUnauthorized() {}

  @Test
  @Ignore
  public void testAuthorizedReadonly() {}

  @Test
  @Ignore
  public void testUnauthorizedReadonly() {}

  @Test
  @Ignore
  public void testTokenForwarding() {}

  @Test
  @Ignore
  public void testRouting() {}
}
