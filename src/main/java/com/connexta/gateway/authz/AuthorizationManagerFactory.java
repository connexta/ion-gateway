/*
 * Copyright (c) 2019 Connexta, LLC
 *
 * Released under the GNU Lesser General Public License version 3; see
 * https://www.gnu.org/licenses/lgpl-3.0.html
 */
package com.connexta.gateway.authz;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

public class AuthorizationManagerFactory {

  private AuthorizationManagerFactory() {}

  public static ReactiveAuthorizationManager<AuthorizationContext> getAuthorizationManager(
      List<String> rules) {

    Map<String, Set<String>> policy = new HashMap<>();
    rules.forEach(
        rule -> {
          String[] kv = rule.split("=", 2);
          if (kv.length == 2) {
            policy.computeIfAbsent(kv[0], key -> new HashSet<>()).add(kv[1]);
          }
        });

    return new ReactiveAuthorizationManager<>() {
      @Override
      public Mono<AuthorizationDecision> check(
          Mono<Authentication> mono, AuthorizationContext context) {
        return mono.map(
                authentication ->
                    authentication.getAuthorities().stream()
                        .filter(authority -> authority instanceof OAuth2UserAuthority)
                        .map(authority -> (OAuth2UserAuthority) authority)
                        .map(OAuth2UserAuthority::getAttributes)
                        .anyMatch(this::isPermitted))
            .map(AuthorizationDecision::new);
      }

      private boolean isPermitted(Map<String, Object> attributes) {
        for(Map.Entry<String, Set<String>> policyEntry : policy.entrySet()) {
          Object claimValue = attributes.get(policyEntry.getKey());
          if (claimValue != null) {
            Collection<?> claimValues = (claimValue instanceof Collection)
                ? (Collection<?>) claimValue
                : Collections.singletonList(claimValue);
            if (claimValues.containsAll(policyEntry.getValue())) {
              continue;
            }
          }
          return false;
        }

        return true;
      }
    };
  }
}
