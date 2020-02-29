/*
 * Copyright (c) 2019 Connexta, LLC
 *
 * Released under the GNU Lesser General Public License version 3; see
 * https://www.gnu.org/licenses/lgpl-3.0.html
 */
package com.connexta.gateway;

import com.connexta.gateway.authz.AuthorizationExchangeCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@EnableWebFluxSecurity
class WebSecurityConfig {

  // NOTE: This code is modeled after ReactiveManagementWebSecurityAutoConfiguration but tailored
  // for OAuth2 browser
  // and bearer token logins

  @Bean
  SecurityWebFilterChain springSecurityFilterChain(
      ServerHttpSecurity http, AuthorizationExchangeCustomizer authorizationExchangeCustomizer) {

    // Disable CSRF
    http.csrf().disable();

    // Allow authenticated requests to any context
    http.authorizeExchange(authorizationExchangeCustomizer);

    // Handle browser redirects to Oauth IDP
    http.oauth2Login();

    // Handle system-to-system Bearer tokens
    http.oauth2ResourceServer().jwt();

    // Use default logout page
    http.logout();

    return http.build();
  }
}
