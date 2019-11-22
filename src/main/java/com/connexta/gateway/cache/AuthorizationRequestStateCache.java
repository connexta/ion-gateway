/*
 * Copyright (c) 2019 Connexta, LLC
 *
 * Released under the GNU Lesser General Public License version 3; see
 * https://www.gnu.org/licenses/lgpl-3.0.html
 */
package com.connexta.gateway.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;

public class AuthorizationRequestStateCache {

  private static final Cache<String, String> stateCache =
      Caffeine.newBuilder().expireAfterWrite(Duration.ofMinutes(10)).build();

  public static void put(String key, String value) {
    stateCache.put(key, value);
  }

  public static String get(String id, boolean remove) {
    String url = stateCache.getIfPresent(id);
    if (remove && url != null) {
      stateCache.invalidate(id);
    }
    return id;
  }
}
