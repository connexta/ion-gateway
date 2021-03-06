/*
 * Copyright (c) 2019 Connexta, LLC
 *
 * Released under the GNU Lesser General Public License version 3; see
 * https://www.gnu.org/licenses/lgpl-3.0.html
 */
package com.connexta.gateway.authz;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

/**
 * A {@link ReactiveAuthorizationManager} that determines whether a user is authorized by evaluating
 * if the {@link Authentication} contains the required scope or its readonly equivalent
 * (scope.readonly).
 *
 * <p>Example: scope=foo Permitted scopes: foo, foo.readonly
 *
 * <p>If the {@link Authentication} contains only a readonly scope, then the method of the {@link
 * AuthorizationContext} must be a "safe" {@link HttpMethod}, as defined by RFC 7231. This can be
 * used to provide only partial access to a user, if needed.
 */
public class ScopeReactiveAuthorizationManager
    implements ReactiveAuthorizationManager<AuthorizationContext> {

  private static final String SCOPE_PREFIX = "SCOPE_";
  private static final String READONLY_REGEX = ".readonly$";
  // HTTP methods defined to be "safe". See https://tools.ietf.org/html/rfc7231#section-4.2.1
  private static final List<HttpMethod> READONLY_METHODS =
      Arrays.asList(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS, HttpMethod.TRACE);

  private final String scope;

  public ScopeReactiveAuthorizationManager(String scope) {
    this.scope = SCOPE_PREFIX + scope;
  }

  @Override
  public Mono<AuthorizationDecision> check(
      Mono<Authentication> mono, AuthorizationContext context) {
    return mono.map(authentication -> this.isAuthorized(authentication, context))
        .map(AuthorizationDecision::new);
  }

  private boolean isAuthorized(Authentication authentication, AuthorizationContext context) {
    List<String> authorities =
        authentication.getAuthorities().stream()
            .map(Object::toString)
            .filter(authority -> authority.split(READONLY_REGEX)[0].equals(scope))
            .distinct()
            .collect(Collectors.toList());

    HttpMethod method = context.getExchange().getRequest().getMethod();
    return !authorities.isEmpty()
        && (authorities.contains(scope) || READONLY_METHODS.contains(method));
  }
}
