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

public class OpenlookengConnectionManager {
  private static final Logger LOG = Logger.getLogger(OpenlookengConnectionManager.class);

  protected ConcurrentMap<String, OpenlookengClient> openlookengConnectionCache;
  protected ConcurrentMap<String, Boolean> repoConnectStatusMap;

  public OpenlookengConnectionManager() {
    openlookengConnectionCache = new ConcurrentHashMap<>();
    repoConnectStatusMap = new ConcurrentHashMap<>();
  }

  public OpenlookengClient getOpenlookengConnection(final String serviceName, final String serviceType, final Map<String, String> configs) {
    OpenlookengClient openlookengClient = null;

    if (serviceType != null) {
      openlookengClient = openlookengConnectionCache.get(serviceName);
      if (openlookengClient == null) {
        if (configs != null) {
          final Callable<OpenlookengClient> connectOpenlookeng = new Callable<OpenlookengClient>() {
            @Override
            public OpenlookengClient call() throws Exception {
              return new OpenlookengClient(serviceName, configs);
            }
          };
          try {
            openlookengClient = TimedEventUtil.timedTask(connectOpenlookeng, 5, TimeUnit.SECONDS);
          } catch (Exception e) {
            LOG.error("Error connecting to Openlookeng repository: " +
            serviceName + " using config: " + configs, e);
          }

          OpenlookengClient oldClient = null;
          if (openlookengClient != null) {
            oldClient = openlookengConnectionCache.putIfAbsent(serviceName, openlookengClient);
          } else {
            oldClient = openlookengConnectionCache.get(serviceName);
          }

          if (oldClient != null) {
            if (openlookengClient != null) {
              openlookengClient.close();
            }
            openlookengClient = oldClient;
          }
          repoConnectStatusMap.put(serviceName, true);
        } else {
          LOG.error("Connection Config not defined for asset :"
            + serviceName, new Throwable());
        }
      } else {
        try {
          openlookengClient.getCatalogList("*", null);
        } catch (Exception e) {
          openlookengConnectionCache.remove(serviceName);
          openlookengClient.close();
          openlookengClient = getOpenlookengConnection(serviceName, serviceType, configs);
        }
      }
    } else {
      LOG.error("Asset not found with name " + serviceName, new Throwable());
    }
    return openlookengClient;
  }
}
