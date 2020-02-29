/*
 * Copyright (c) 2019 Connexta, LLC
 *
 * Released under the GNU Lesser General Public License version 3; see
 * https://www.gnu.org/licenses/lgpl-3.0.html
 */
package com.connexta.gateway.authz;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.stereotype.Component;

/**
 * Customizes the {@link AuthorizeExchangeSpec} with a set of authorization managers according to
 * the web context policy. If provided {@link WebContextPolicy} is null, access control will be
 * disabled. All requests from authenticated clients will be permitted.
 */
@Component
public class AuthorizationExchangeCustomizer implements Customizer<AuthorizeExchangeSpec> {

  private WebContextPolicy webContextPolicy;

  @Autowired
  public AuthorizationExchangeCustomizer(WebContextPolicy webContextPolicy) {
    this.webContextPolicy = webContextPolicy;
  }

  @Override
  public void customize(AuthorizeExchangeSpec authorizeExchangeSpec) {
    if (webContextPolicy != null
        && webContextPolicy.getPolicy() != null
        && !webContextPolicy.getPolicy().isEmpty()) {
      for (PolicyEntry entry : webContextPolicy.getPolicy()) {
        authorizeExchangeSpec
            .pathMatchers(entry.getPattern())
            .access(new ScopeReactiveAuthorizationManager(entry.getScope()));
      }
    }

    // Fallback if no path matchers apply
    authorizeExchangeSpec.anyExchange().authenticated();
  }
}
