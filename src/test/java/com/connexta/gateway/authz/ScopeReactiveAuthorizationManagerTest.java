/*
 * Copyright (c) 2019 Connexta, LLC
 *
 * Released under the GNU Lesser General Public License version 3; see
 * https://www.gnu.org/licenses/lgpl-3.0.html
 */
package com.connexta.gateway.authz;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class ScopeReactiveAuthorizationManagerTest {

  private Mono<Authentication> initAuthentication(List<String> authorities) {
    Collection<? extends GrantedAuthority> grantedAuthorities =
        authorities.stream()
            .map(
                authority -> {
                  GrantedAuthority grantedAuthority = mock(GrantedAuthority.class);
                  when(grantedAuthority.getAuthority()).thenReturn(authority);
                  return grantedAuthority;
                })
            .collect(Collectors.toList());

    Authentication authentication = mock(Authentication.class);
    when(authentication.getAuthorities()).thenAnswer(invocationOnMock -> grantedAuthorities);
    return Mono.just(authentication);
  }

  private AuthorizationContext initAuthorizationContext(HttpMethod httpMethod) {
    AuthorizationContext context = mock(AuthorizationContext.class);
    ServerWebExchange exchange = mock(ServerWebExchange.class);
    ServerHttpRequest request = mock(ServerHttpRequest.class);
    when(request.getMethod()).thenReturn(httpMethod);
    when(exchange.getRequest()).thenReturn(request);
    when(context.getExchange()).thenReturn(exchange);
    return context;
  }

  private boolean getAuthorizationDecision(
      ScopeReactiveAuthorizationManager scopeReactiveAuthorizationManager,
      Mono<Authentication> authentication,
      AuthorizationContext context) {
    Mono<AuthorizationDecision> decisionMono =
        scopeReactiveAuthorizationManager.check(authentication, context);
    List<AuthorizationDecision> decision = new ArrayList<>();
    decisionMono.subscribe(decision::add);
    return decision.get(0).isGranted();
  }

  @Test
  public void testAuthorized() {
    Mono<Authentication> authentication =
        initAuthentication(Arrays.asList("SCOPE_openid", "SCOPE_email", "SCOPE_profile"));
    AuthorizationContext context = initAuthorizationContext(HttpMethod.GET);
    ScopeReactiveAuthorizationManager authorizationManager =
        new ScopeReactiveAuthorizationManager("openid");

    boolean decision = getAuthorizationDecision(authorizationManager, authentication, context);
    assertThat(decision, is(true));
  }

  @Test
  public void testUnauthorized() {
    Mono<Authentication> authentication =
        initAuthentication(Arrays.asList("SCOPE_email", "SCOPE_profile"));
    AuthorizationContext context = initAuthorizationContext(HttpMethod.GET);
    ScopeReactiveAuthorizationManager authorizationManager =
        new ScopeReactiveAuthorizationManager("openid");

    boolean decision = getAuthorizationDecision(authorizationManager, authentication, context);
    assertThat(decision, is(false));
  }

  @Test
  public void testAuthorizedReadonly() {
    Mono<Authentication> authentication =
        initAuthentication(Collections.singletonList("SCOPE_email.readonly"));
    AuthorizationContext context = initAuthorizationContext(HttpMethod.GET);
    ScopeReactiveAuthorizationManager authorizationManager =
        new ScopeReactiveAuthorizationManager("email");

    boolean decision = getAuthorizationDecision(authorizationManager, authentication, context);
    assertThat(decision, is(true));
  }

  @Test
  public void testUnauthorizedReadonly() {
    Mono<Authentication> authentication =
        initAuthentication(Collections.singletonList("SCOPE_email.readonly"));
    AuthorizationContext context = initAuthorizationContext(HttpMethod.POST);
    ScopeReactiveAuthorizationManager authorizationManager =
        new ScopeReactiveAuthorizationManager("email");

    boolean decision = getAuthorizationDecision(authorizationManager, authentication, context);
    assertThat(decision, is(false));
  }

  @Test
  public void testMissingScopePrefix() {
    Mono<Authentication> authentication = initAuthentication(Collections.singletonList("email"));
    AuthorizationContext context = initAuthorizationContext(HttpMethod.GET);
    ScopeReactiveAuthorizationManager authorizationManager =
        new ScopeReactiveAuthorizationManager("email");

    boolean decision = getAuthorizationDecision(authorizationManager, authentication, context);
    assertThat(decision, is(false));
  }

  @Test
  public void testNoAuthorities() {
    Mono<Authentication> authentication = initAuthentication(Collections.emptyList());
    AuthorizationContext context = initAuthorizationContext(HttpMethod.GET);
    ScopeReactiveAuthorizationManager authorizationManager =
        new ScopeReactiveAuthorizationManager("email");

    boolean decision = getAuthorizationDecision(authorizationManager, authentication, context);
    assertThat(decision, is(false));
  }

  @Test
  public void testNoAuthoritiesNullScope() {
    Mono<Authentication> authentication = initAuthentication(Collections.emptyList());
    AuthorizationContext context = initAuthorizationContext(HttpMethod.GET);
    ScopeReactiveAuthorizationManager authorizationManager =
        new ScopeReactiveAuthorizationManager(null);

    boolean decision = getAuthorizationDecision(authorizationManager, authentication, context);
    assertThat(decision, is(true));
  }
}
