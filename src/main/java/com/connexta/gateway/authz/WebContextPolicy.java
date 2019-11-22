/*
 * Copyright (c) 2019 Connexta, LLC
 *
 * Released under the GNU Lesser General Public License version 3; see
 * https://www.gnu.org/licenses/lgpl-3.0.html
 */
package com.connexta.gateway.authz;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "web.context")
public class WebContextPolicy {

  private List<PolicyEntry> policy;

  public List<PolicyEntry> getPolicy() {
    return policy;
  }

  public void setPolicy(List<PolicyEntry> policy) {
    this.policy = policy;
  }
}
