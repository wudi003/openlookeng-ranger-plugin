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
package org.apache.ranger.authorization.openlookeng.authorizer;

import io.prestosql.spi.connector.CatalogSchemaName;
import io.prestosql.spi.connector.CatalogSchemaTableName;
import io.prestosql.spi.connector.ColumnMetadata;
import io.prestosql.spi.connector.SchemaTableName;
import io.prestosql.spi.security.AccessDeniedException;
import io.prestosql.spi.security.Identity;
import io.prestosql.spi.security.PrestoPrincipal;
import io.prestosql.spi.security.Privilege;
import io.prestosql.spi.security.SystemAccessControl;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Locale.ENGLISH;

public class RangerSystemAccessControl
  implements SystemAccessControl {
  private static Logger LOG = LoggerFactory.getLogger(RangerSystemAccessControl.class);

  final public static String RANGER_CONFIG_KEYTAB = "ranger.keytab";
  final public static String RANGER_CONFIG_PRINCIPAL = "ranger.principal";
  final public static String RANGER_CONFIG_USE_UGI = "ranger.use_ugi";
  final public static String RANGER_CONFIG_HADOOP_CONFIG = "ranger.hadoop_config";
  final public static String RANGER_OPENLOOKENG_DEFAULT_HADOOP_CONF = "openlookeng-ranger-site.xml";
  final public static String RANGER_OPENLOOKENG_SERVICETYPE = "openlookeng";
  final public static String RANGER_OPENLOOKENG_APPID = "openlookeng";

  final private RangerBasePlugin rangerPlugin;

  private boolean useUgi = false;

  public RangerSystemAccessControl(Map<String, String> config) {
    super();

    Configuration hadoopConf = new Configuration();
    if (config.get(RANGER_CONFIG_HADOOP_CONFIG) != null) {
      URL url =  hadoopConf.getResource(config.get(RANGER_CONFIG_HADOOP_CONFIG));
      if (url == null) {
        LOG.warn("Hadoop config " + config.get(RANGER_CONFIG_HADOOP_CONFIG) + " not found");
      } else {
        hadoopConf.addResource(url);
      }
    } else {
      URL url = hadoopConf.getResource(RANGER_OPENLOOKENG_DEFAULT_HADOOP_CONF);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Trying to load Hadoop config from " + url + " (can be null)");
      }
      if (url != null) {
        hadoopConf.addResource(url);
      }
    }
    UserGroupInformation.setConfiguration(hadoopConf);

    if (config.get(RANGER_CONFIG_KEYTAB) != null && config.get(RANGER_CONFIG_PRINCIPAL) != null) {
      String keytab = config.get(RANGER_CONFIG_KEYTAB);
      String principal = config.get(RANGER_CONFIG_PRINCIPAL);

      LOG.info("Performing kerberos login with principal " + principal + " and keytab " + keytab);

      try {
        UserGroupInformation.loginUserFromKeytab(principal, keytab);
      } catch (IOException ioe) {
        LOG.error("Kerberos login failed", ioe);
        throw new RuntimeException(ioe);
      }
    }

    if (config.getOrDefault(RANGER_CONFIG_USE_UGI, "false").equalsIgnoreCase("true")) {
      useUgi = true;
    }

    rangerPlugin = new RangerBasePlugin(RANGER_OPENLOOKENG_SERVICETYPE, RANGER_OPENLOOKENG_APPID);
    rangerPlugin.init();
    rangerPlugin.setResultProcessor(new RangerDefaultAuditHandler());
  }

  @Override
  public Set<String> filterCatalogs(Identity identity, Set<String> catalogs) {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerSystemAccessControl.filterCatalogs("+ catalogs + ")");
    }
    Set<String> filteredCatalogs = new HashSet<>(catalogs.size());
    for (String catalog: catalogs) {
      if (hasPermission(createResource(catalog), identity, OpenLooKengAccessType.SELECT)) {
        filteredCatalogs.add(catalog);
      }
    }
    return filteredCatalogs;
  }

  @Override
  public Set<String> filterSchemas(Identity identity, String catalogName, Set<String> schemaNames) {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerSystemAccessControl.filterSchemas(" + catalogName + ")");
    }
    Set<String> filteredSchemaNames = new HashSet<>(schemaNames.size());
    for (String schemaName: schemaNames) {
      if (hasPermission(createResource(catalogName, schemaName), identity, OpenLooKengAccessType.SELECT)) {
        filteredSchemaNames.add(schemaName);
      }
    }
    return filteredSchemaNames;
  }

  @Override
  public Set<SchemaTableName> filterTables(Identity identity, String catalogName, Set<SchemaTableName> tableNames) {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerSystemAccessControl.filterTables(" + catalogName + ")");
    }
    Set<SchemaTableName> filteredTableNames = new HashSet<>(tableNames.size());
    for (SchemaTableName tableName : tableNames) {
      RangerOpenLooKengResource res = createResource(catalogName, tableName.getSchemaName(), tableName.getTableName());
      if (hasPermission(res, identity, OpenLooKengAccessType.SELECT)) {
        filteredTableNames.add(tableName);
      }
    }
    return filteredTableNames;
  }

  @Override
  public List<ColumnMetadata> filterColumns(Identity identity, CatalogSchemaTableName table, List<ColumnMetadata> columns) {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerSystemAccessControl.filterColumns(" + table.getCatalogName() + ")");
    }
    List<ColumnMetadata> filteredColumnNames = new ArrayList<>(columns.size());
    for (ColumnMetadata columnMetadata : columns) {
      RangerOpenLooKengResource res = createResource(table, Optional.of(columnMetadata.getName()));
      if (hasPermission(res, identity, OpenLooKengAccessType.SELECT)) {
        filteredColumnNames.add(columnMetadata);
      }
    }
    return filteredColumnNames;
  }

  /** PERMISSION CHECKS ORDERED BY SYSTEM, CATALOG, SCHEMA, TABLE, VIEW, COLUMN **/

  /** SYSTEM **/

  @Override
  public void checkCanSetUser(Optional<Principal> principal, String userName) {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerSystemAccessControl.checkCanSetUser(" + userName + ")");
    }
  }

  @Override
  public void checkCanSetSystemSessionProperty(Identity identity, String propertyName) {
    if (!hasPermission(createSystemPropertyResource(propertyName), identity, OpenLooKengAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanSetSystemSessionProperty denied");
      AccessDeniedException.denySetSystemSessionProperty(propertyName);
    }
  }

  /** CATALOG **/

  @Override
  public void checkCanSetCatalogSessionProperty(Identity identity, String catalogName, String propertyName) {
    if (!hasPermission(createCatalogSessionResource(catalogName, propertyName), identity, OpenLooKengAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanSetSystemSessionProperty(" + catalogName + ") denied");
      AccessDeniedException.denySetCatalogSessionProperty(catalogName, propertyName);
    }
  }

  @Override
  public void checkCanShowCatalogs(Identity identity) {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerSystemAccessControl.checkCanShowCatalogs, identity user : " + identity.getUser());
    }
  }

  @Override
  public void checkCanAccessCatalog(Identity identity, String catalogName) {
    if (!hasPermission(createResource(catalogName), identity, OpenLooKengAccessType.USE)) {
      LOG.debug("RangerSystemAccessControl.checkCanAccessCatalog(" + catalogName + ") denied");
      AccessDeniedException.denyCatalogAccess(catalogName);
    }
  }

  @Override
  public void checkCanCreateCatalog(Identity identity, String catalogName) {
    if (!hasPermission(createResource(catalogName), identity, OpenLooKengAccessType.CREATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateCatalog(" + catalogName + ") denied");
      AccessDeniedException.denyCreateCatalog(catalogName);
    }
  }

  @Override
  public void checkCanDropCatalog(Identity identity, String catalogName) {
    if (!hasPermission(createResource(catalogName), identity, OpenLooKengAccessType.DROP)) {
      LOG.debug("RangerSystemAccessControl.checkCanDropCatalog(" + catalogName + ") denied");
      AccessDeniedException.denyDropCatalog(catalogName);
    }
  }

  @Override
  public void checkCanUpdateCatalog(Identity identity, String catalogName) {
    if (!hasPermission(createResource(catalogName), identity, OpenLooKengAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanUpdateCatalog(" + catalogName + ") denied");
      AccessDeniedException.denyUpdateCatalog(catalogName);
    }
  }

  @Override
  public void checkCanShowRoles(Identity identity, String catalogName) {
    if (!hasPermission(createResource(catalogName), identity, OpenLooKengAccessType.SHOW)) {
      LOG.debug("RangerSystemAccessControl.checkCanShowRoles(" + catalogName + ") denied");
      AccessDeniedException.denyShowRoles(catalogName);
    }
  }

  @Override
  public void checkCanShowSchemas(Identity identity, String catalogName) {
    if (!hasPermission(createResource(catalogName), identity, OpenLooKengAccessType.SHOW)) {
      LOG.debug("RangerSystemAccessControl.checkCanShowSchemas(" + catalogName + ") denied");
      AccessDeniedException.denyShowSchemas(catalogName);
    }
  }

  /** SCHEMA **/

  /**
   * Create schema is evaluated on the level of the Catalog. This means that it is assumed you have permission
   * to create a schema when you have create rights on the catalog level
   */
  @Override
  public void checkCanCreateSchema(Identity identity, CatalogSchemaName schema) {
    if (!hasPermission(createResource(schema.getCatalogName()), identity, OpenLooKengAccessType.CREATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyCreateSchema(schema.getSchemaName());
    }
  }

  /**
   * This is evaluated against the schema name as ownership information is not available
   */
  @Override
  public void checkCanDropSchema(Identity identity, CatalogSchemaName schema) {
    if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), identity, OpenLooKengAccessType.DROP)) {
      LOG.debug("RangerSystemAccessControl.checkCanDropSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyDropSchema(schema.getSchemaName());
    }
  }

  /**
   * This is evaluated against the schema name as ownership information is not available
   */
  @Override
  public void checkCanRenameSchema(Identity identity, CatalogSchemaName schema, String newSchemaName) {
    if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), identity, OpenLooKengAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanRenameSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyRenameSchema(schema.getSchemaName(), newSchemaName);
    }
  }

  /** TABLE **/

  /**
   * Show tables is verified on schema level
   */
  @Override
  public void checkCanShowTablesMetadata(Identity identity, CatalogSchemaName schema) {
    if (!hasPermission(createResource(schema), identity, OpenLooKengAccessType.SHOW)) {
      LOG.debug("RangerSystemAccessControl.checkCanShowTables(" + schema.toString() + ") denied");
      AccessDeniedException.denyShowTablesMetadata(schema.toString());
    }
  }

  /**
   * Create table is verified on schema level
   */
  @Override
  public void checkCanCreateTable(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table.getCatalogName(), table.getSchemaTableName().getSchemaName()), identity, OpenLooKengAccessType.CREATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanUpdateTable(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, OpenLooKengAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanUpdateTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyUpdateTable(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated against the table name as ownership information is not available
   */
  @Override
  public void checkCanDropTable(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, OpenLooKengAccessType.DROP)) {
      LOG.debug("RangerSystemAccessControl.checkCanDropTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDropTable(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated against the table name as ownership information is not available
   */
  @Override
  public void checkCanRenameTable(Identity identity, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
    if (!hasPermission(createResource(table), identity, OpenLooKengAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanRenameTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanInsertIntoTable(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, OpenLooKengAccessType.INSERT)) {
      LOG.debug("RangerSystemAccessControl.checkCanInsertIntoTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyInsertTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDeleteFromTable(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, OpenLooKengAccessType.DELETE)) {
      LOG.debug("RangerSystemAccessControl.checkCanDeleteFromTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanGrantTablePrivilege(Identity identity, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal grantee, boolean withGrantOption) {
    if (!hasPermission(createResource(table), identity, OpenLooKengAccessType.GRANT)) {
      LOG.debug("RangerSystemAccessControl.checkCanGrantTablePrivilege(" + table + ") denied");
      AccessDeniedException.denyGrantTablePrivilege(privilege.toString(), table.toString());
    }
  }

  @Override
  public void checkCanRevokeTablePrivilege(Identity identity, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal revokee, boolean grantOptionFor) {
    if (!hasPermission(createResource(table), identity, OpenLooKengAccessType.REVOKE)) {
      LOG.debug("RangerSystemAccessControl.checkCanRevokeTablePrivilege(" + table + ") denied");
      AccessDeniedException.denyRevokeTablePrivilege(privilege.toString(), table.toString());
    }
  }

  @Override
  public void checkCanSetTableComment(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, OpenLooKengAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanSetTableComment(" + table.toString() + ") denied");
      AccessDeniedException.denyCommentTable(table.toString());
    }
  }

  /**
   * Create view is verified on schema level
   */
  @Override
  public void checkCanCreateView(Identity identity, CatalogSchemaTableName view) {
    if (!hasPermission(createResource(view.getCatalogName(), view.getSchemaTableName().getSchemaName()), identity, OpenLooKengAccessType.CREATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateView(" + view.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated against the table name as ownership information is not available
   */
  @Override
  public void checkCanDropView(Identity identity, CatalogSchemaTableName view) {
    if (!hasPermission(createResource(view), identity, OpenLooKengAccessType.DROP)) {
      LOG.debug("RangerSystemAccessControl.checkCanDropView(" + view.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }
  }

  /**
   * This check equals the check for checkCanCreateView
   */
  @Override
  public void checkCanCreateViewWithSelectFromColumns(Identity identity, CatalogSchemaTableName table, Set<String> columns) {
    try {
      checkCanCreateView(identity, table);
    } catch (AccessDeniedException ade) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateViewWithSelectFromColumns(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateViewWithSelect(table.getSchemaTableName().getTableName(), identity);
    }
  }

  /** COLUMN **/

  /**
   * This is evaluated on table level
   */
  @Override
  public void checkCanAddColumn(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, OpenLooKengAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanAddColumn(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated on table level
   */
  @Override
  public void checkCanDropColumn(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, OpenLooKengAccessType.DROP)) {
      LOG.debug("RangerSystemAccessControl.checkCanDropColumn(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDropColumn(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated on table level
   */
  @Override
  public void checkCanRenameColumn(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, OpenLooKengAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanRenameColumn(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyRenameColumn(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated on table level
   */
  @Override
  public void checkCanShowColumnsMetadata (Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, OpenLooKengAccessType.SHOW)) {
      LOG.debug("RangerSystemAccessControl.checkCanShowColumnsMetadata(" + table.toString() + ") denied");
      AccessDeniedException.denyShowColumnsMetadata(table.toString());
    }
  }

  @Override
  public void checkCanSelectFromColumns(Identity identity, CatalogSchemaTableName table, Set<String> columns) {
    for (RangerOpenLooKengResource res : createResource(table, columns)) {
      if (!hasPermission(res, identity, OpenLooKengAccessType.SELECT)) {
        LOG.debug("RangerSystemAccessControl.checkCanSelectFromColumns(" + table.getSchemaTableName().getTableName() + ") denied");
        AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
      }
    }
  }

  @Override
  public void checkCanAccessNodeInfo(Identity identity) {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerSystemAccessControl.checkCanAccessNodeInfo(" + identity.getUser() + ")");
    }
  }

  /** HELPER FUNCTIONS **/

  private RangerOpenLooKengAccessRequest createAccessRequest(RangerOpenLooKengResource resource, Identity identity, OpenLooKengAccessType accessType) {
    Set<String> userGroups = null;

    if (useUgi) {
      UserGroupInformation ugi = UserGroupInformation.createRemoteUser(identity.getUser());

      String[] groups = ugi != null ? ugi.getGroupNames() : null;

      if (groups != null && groups.length > 0) {
        userGroups = new HashSet<>(Arrays.asList(groups));
      }
    }

    RangerOpenLooKengAccessRequest request = new RangerOpenLooKengAccessRequest(
      resource,
      identity.getUser(),
      userGroups,
      accessType
    );

    return request;
  }

  private boolean hasPermission(RangerOpenLooKengResource resource, Identity identity, OpenLooKengAccessType accessType) {
    boolean ret = false;

    RangerOpenLooKengAccessRequest request = createAccessRequest(resource, identity, accessType);

    RangerAccessResult result = rangerPlugin.isAccessAllowed(request);
    if (result != null && result.getIsAllowed()) {
      ret = true;
    }

    return ret;
  }

  private static RangerOpenLooKengResource createCatalogSessionResource(String catalogName, String propertyName) {
    RangerOpenLooKengResource res = new RangerOpenLooKengResource();
    res.setValue(RangerOpenLooKengResource.KEY_CATALOG, catalogName);
    res.setValue(RangerOpenLooKengResource.KEY_SESSION_PROPERTY, propertyName);

    return res;
  }

  private static RangerOpenLooKengResource createSystemPropertyResource(String property) {
    RangerOpenLooKengResource res = new RangerOpenLooKengResource();
    res.setValue(RangerOpenLooKengResource.KEY_SYSTEM_PROPERTY, property);

    return res;
  }

  private static RangerOpenLooKengResource createResource(CatalogSchemaName catalogSchemaName) {
    return createResource(catalogSchemaName.getCatalogName(), catalogSchemaName.getSchemaName());
  }

  private static RangerOpenLooKengResource createResource(CatalogSchemaTableName catalogSchemaTableName) {
    return createResource(catalogSchemaTableName.getCatalogName(),
      catalogSchemaTableName.getSchemaTableName().getSchemaName(),
      catalogSchemaTableName.getSchemaTableName().getTableName());
  }

  private static RangerOpenLooKengResource createResource(CatalogSchemaTableName catalogSchemaTableName, final Optional<String> column) {
    return createResource(catalogSchemaTableName.getCatalogName(),
            catalogSchemaTableName.getSchemaTableName().getSchemaName(),
            catalogSchemaTableName.getSchemaTableName().getTableName(),
            column);
  }

  private static RangerOpenLooKengResource createResource(String catalogName) {
    return new RangerOpenLooKengResource(catalogName, Optional.empty(), Optional.empty());
  }

  private static RangerOpenLooKengResource createResource(String catalogName, String schemaName) {
    return new RangerOpenLooKengResource(catalogName, Optional.of(schemaName), Optional.empty());
  }

  private static RangerOpenLooKengResource createResource(String catalogName, String schemaName, final String tableName) {
    return new RangerOpenLooKengResource(catalogName, Optional.of(schemaName), Optional.of(tableName));
  }

  private static RangerOpenLooKengResource createResource(String catalogName, String schemaName, final String tableName, final Optional<String> column) {
    return new RangerOpenLooKengResource(catalogName, Optional.of(schemaName), Optional.of(tableName), column);
  }

  private static List<RangerOpenLooKengResource> createResource(CatalogSchemaTableName table, Set<String> columns) {
    List<RangerOpenLooKengResource> colRequests = new ArrayList<>();

    if (columns.size() > 0) {
      for (String column : columns) {
        RangerOpenLooKengResource rangerOpenLooKengResource = createResource(table.getCatalogName(),
          table.getSchemaTableName().getSchemaName(),
          table.getSchemaTableName().getTableName(), Optional.of(column));
        colRequests.add(rangerOpenLooKengResource);
      }
    } else {
      colRequests.add(createResource(table.getCatalogName(),
        table.getSchemaTableName().getSchemaName(),
        table.getSchemaTableName().getTableName(), Optional.empty()));
    }
    return colRequests;
  }
}

class RangerOpenLooKengResource
        extends RangerAccessResourceImpl {


  public static final String KEY_CATALOG = "catalog";
  public static final String KEY_SCHEMA = "schema";
  public static final String KEY_TABLE = "table";
  public static final String KEY_COLUMN = "column";
  public static final String KEY_SYSTEM_PROPERTY = "systemproperty";
  public static final String KEY_SESSION_PROPERTY = "sessionproperty";

  public RangerOpenLooKengResource() {
  }

  public RangerOpenLooKengResource(String catalogName, Optional<String> schema, Optional<String> table) {
    setValue(KEY_CATALOG, catalogName);
    if (schema.isPresent()) {
      setValue(KEY_SCHEMA, schema.get());
    }
    if (table.isPresent()) {
      setValue(KEY_TABLE, table.get());
    }
  }

  public RangerOpenLooKengResource(String catalogName, Optional<String> schema, Optional<String> table, Optional<String> column) {
    setValue(KEY_CATALOG, catalogName);
    if (schema.isPresent()) {
      setValue(KEY_SCHEMA, schema.get());
    }
    if (table.isPresent()) {
      setValue(KEY_TABLE, table.get());
    }
    if (column.isPresent()) {
      setValue(KEY_COLUMN, column.get());
    }
  }

  public String getCatalogName() {
    return (String) getValue(KEY_CATALOG);
  }

  public String getTable() {
    return (String) getValue(KEY_TABLE);
  }

  public String getCatalog() {
    return (String) getValue(KEY_CATALOG);
  }

  public String getSchema() {
    return (String) getValue(KEY_SCHEMA);
  }

  public Optional<SchemaTableName> getSchemaTable() {
    final String schema = getSchema();
    if (StringUtils.isNotEmpty(schema)) {
      return Optional.of(new SchemaTableName(schema, Optional.ofNullable(getTable()).orElse("*")));
    }
    return Optional.empty();
  }
}

class RangerOpenLooKengAccessRequest
        extends RangerAccessRequestImpl {
  public RangerOpenLooKengAccessRequest(RangerOpenLooKengResource resource,
                                        String user,
                                        Set<String> userGroups,
                                        OpenLooKengAccessType openLooKengAccessType) {
    super(resource, openLooKengAccessType.name().toLowerCase(ENGLISH), user, userGroups, null);
    setAccessTime(new Date());
  }
}

enum OpenLooKengAccessType
{
  CREATE, DROP, SELECT, INSERT, DELETE, USE, ALTER, ALL, GRANT, REVOKE, SHOW;
}