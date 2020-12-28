/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.ranger.services.openlookeng.client;

import org.apache.log4j.Logger;
import org.apache.ranger.plugin.util.TimedEventUtil;

import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

public class OpenLooKengConnectionManager
{
  private static final Logger LOG = Logger.getLogger(OpenLooKengConnectionManager.class);

  protected ConcurrentMap<String, OpenLooKengClient> openLooKengConnectionCache;
  protected ConcurrentMap<String, Boolean> repoConnectStatusMap;

  public OpenLooKengConnectionManager() {
    openLooKengConnectionCache = new ConcurrentHashMap<>();
    repoConnectStatusMap = new ConcurrentHashMap<>();
  }

  public OpenLooKengClient getOpenLooKengConnection(final String serviceName, final String serviceType, final Map<String, String> configs) {
    OpenLooKengClient openLooKengClient = null;

    if (serviceType != null) {
      openLooKengClient = openLooKengConnectionCache.get(serviceName);
      if (openLooKengClient == null) {
        if (configs != null) {
          final Callable<OpenLooKengClient> connectOpenLooKeng = new Callable<OpenLooKengClient>() {
            @Override
            public OpenLooKengClient call() throws Exception {
              return new OpenLooKengClient(serviceName, configs);
            }
          };
          try {
            openLooKengClient = TimedEventUtil.timedTask(connectOpenLooKeng, 5, TimeUnit.SECONDS);
          } catch (Exception e) {
            LOG.error("Error connecting to openLooKeng repository: " +
            serviceName + " using config: " + configs, e);
          }

          OpenLooKengClient oldClient = null;
          if (openLooKengClient != null) {
            oldClient = openLooKengConnectionCache.putIfAbsent(serviceName, openLooKengClient);
          } else {
            oldClient = openLooKengConnectionCache.get(serviceName);
          }

          if (oldClient != null) {
            if (openLooKengClient != null) {
              openLooKengClient.close();
            }
            openLooKengClient = oldClient;
          }
          repoConnectStatusMap.put(serviceName, true);
        } else {
          LOG.error("Connection Config not defined for asset :"
            + serviceName, new Throwable());
        }
      } else {
        try {
          openLooKengClient.getCatalogList("*", null);
        } catch (Exception e) {
          openLooKengConnectionCache.remove(serviceName);
          openLooKengClient.close();
          openLooKengClient = getOpenLooKengConnection(serviceName, serviceType, configs);
        }
      }
    } else {
      LOG.error("Asset not found with name " + serviceName, new Throwable());
    }
    return openLooKengClient;
  }
}
