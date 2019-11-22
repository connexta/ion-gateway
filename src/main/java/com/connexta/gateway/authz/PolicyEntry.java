/*
 * Copyright (c) 2019 Connexta, LLC
 *
 * Released under the GNU Lesser General Public License version 3; see
 * https://www.gnu.org/licenses/lgpl-3.0.html
 */
package com.connexta.gateway.authz;

import java.util.List;

public class PolicyEntry {
  private String context;
  private List<String> rules;

  public String getContext() {
    return context;
  }

  public void setContext(String context) {
    this.context = context;
  }

  public List<String> getRules() {
    return rules;
  }

  public void setRules(List<String> rules) {
    this.rules = rules;
  }
}
