/*
 * Copyright (c) 2019 Connexta, LLC
 *
 * Released under the GNU Lesser General Public License version 3; see
 * https://www.gnu.org/licenses/lgpl-3.0.html
 */
package com.connexta.gateway;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;

@Controller
public class WhoamiController {

  @GetMapping("/whoami")
  public String index(Model model, Authentication authentication) {
    if (authentication instanceof JwtAuthenticationToken) {
      // Client provided JWT bearer token
      JwtAuthenticationToken token = (JwtAuthenticationToken) authentication;
      model.addAttribute("userName", token.getName());
      model.addAttribute("clientRegistrationId", "N/A");
      model.addAttribute("userAttributes", token.getTokenAttributes());
    } else if (authentication instanceof OAuth2AuthenticationToken) {
      // Client logged in via browser flow
      OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
      model.addAttribute("userName", token.getName());
      model.addAttribute("clientRegistrationId", token.getAuthorizedClientRegistrationId());
      model.addAttribute("userAttributes", token.getPrincipal().getAttributes());
    } else {
      String message = (authentication == null) ? "null" : authentication.toString();
      throw new UnresolvedPrincipalException(message);
    }

    model.addAttribute("grantedAuthorities", authentication.getAuthorities());
    return "index";
  }

  @ResponseStatus(
      value = HttpStatus.INTERNAL_SERVER_ERROR,
      reason = "Received null or unsupported auth token")
  private static class UnresolvedPrincipalException extends RuntimeException {
    public UnresolvedPrincipalException(String message) {
      super(message);
    }
  }
}
