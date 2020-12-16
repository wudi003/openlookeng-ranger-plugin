/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.ranger.authorization.openlookeng.authorizer;

import com.google.common.collect.ImmutableSet;
import io.prestosql.spi.connector.CatalogSchemaName;
import io.prestosql.spi.connector.CatalogSchemaTableName;
import io.prestosql.spi.connector.SchemaTableName;
import io.prestosql.spi.security.AccessDeniedException;
import io.prestosql.spi.security.Identity;
import io.prestosql.spi.security.PrestoPrincipal;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static io.prestosql.spi.security.PrincipalType.USER;
import static io.prestosql.spi.security.Privilege.SELECT;
import static org.junit.Assert.assertEquals;

public class RangerSystemAccessControlTest {
  static RangerSystemAccessControl accessControlManager = null;

  private static final Identity alice = new Identity("alice", Optional.empty());
  private static final Identity bob = new Identity("bob", Optional.empty());

  private static final Set<String> allCatalogs = ImmutableSet.of("open-to-all", "all-allowed", "alice-catalog");
  private static final String aliceCatalog = "alice-catalog";
  private static final CatalogSchemaName aliceSchema = new CatalogSchemaName("alice-catalog", "schema");
  private static final CatalogSchemaTableName aliceTable = new CatalogSchemaTableName("alice-catalog", "schema","table");
  private static final CatalogSchemaTableName aliceView = new CatalogSchemaTableName("alice-catalog", "schema","view");

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    Map<String, String> config = new HashMap<>();
    accessControlManager = new RangerSystemAccessControl(config);
  }

  @Test
  public void testCatalogOperations()
  {
    assertEquals(accessControlManager.filterCatalogs(alice, allCatalogs), allCatalogs);
    Set<String> bobCatalogs = ImmutableSet.of("open-to-all", "all-allowed");
    assertEquals(accessControlManager.filterCatalogs(bob, allCatalogs), bobCatalogs);
  }

  @Test
  @SuppressWarnings("PMD")
  public void testSchemaOperations()
  {

    Set<String> aliceSchemas = ImmutableSet.of("schema");
    assertEquals(accessControlManager.filterSchemas(alice, aliceCatalog, aliceSchemas), aliceSchemas);
    assertEquals(accessControlManager.filterSchemas(bob, "alice-catalog", aliceSchemas), ImmutableSet.of());

    accessControlManager.checkCanCreateSchema(alice, aliceSchema);
    accessControlManager.checkCanDropSchema(alice, aliceSchema);
    accessControlManager.checkCanRenameSchema(alice, aliceSchema, "new-schema");
    accessControlManager.checkCanShowSchemas(alice, aliceCatalog);

    try {
      accessControlManager.checkCanCreateSchema(bob, aliceSchema);
    } catch (AccessDeniedException expected) {
    }
  }

  @Test
  @SuppressWarnings("PMD")
  public void testTableOperations()
  {
    Set<SchemaTableName> aliceTables = ImmutableSet.of(new SchemaTableName("schema", "table"));
    assertEquals(accessControlManager.filterTables(alice, aliceCatalog, aliceTables), aliceTables);
    assertEquals(accessControlManager.filterTables(bob, "alice-catalog", aliceTables), ImmutableSet.of());

    accessControlManager.checkCanCreateTable(alice, aliceTable);
    accessControlManager.checkCanDropTable(alice, aliceTable);
    accessControlManager.checkCanSelectFromColumns(alice, aliceTable, ImmutableSet.of());
    accessControlManager.checkCanInsertIntoTable(alice, aliceTable);
    accessControlManager.checkCanDeleteFromTable(alice, aliceTable);
    accessControlManager.checkCanRenameColumn(alice, aliceTable);


    try {
      accessControlManager.checkCanCreateTable(bob, aliceTable);
    } catch (AccessDeniedException expected) {
    }
  }

  @Test
  @SuppressWarnings("PMD")
  public void testViewOperations()
  {
    accessControlManager.checkCanCreateView(alice, aliceView);
    accessControlManager.checkCanDropView(alice, aliceView);
    accessControlManager.checkCanSelectFromColumns(alice, aliceView, ImmutableSet.of());
    accessControlManager.checkCanCreateViewWithSelectFromColumns(alice, aliceTable, ImmutableSet.of());
    accessControlManager.checkCanCreateViewWithSelectFromColumns(alice, aliceView, ImmutableSet.of());
    accessControlManager.checkCanSetCatalogSessionProperty(alice, aliceCatalog, "property");
    accessControlManager.checkCanGrantTablePrivilege(alice, SELECT, aliceTable, new PrestoPrincipal(USER, "grantee"), true);
    accessControlManager.checkCanRevokeTablePrivilege(alice, SELECT, aliceTable, new PrestoPrincipal(USER, "revokee"), true);

    try {
      accessControlManager.checkCanCreateView(bob, aliceView);
    } catch (AccessDeniedException expected) {
    }
  }
}