/*
 * Licensed to Crate under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.  Crate licenses this file
 * to you under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * However, if you have executed another commercial license agreement
 * with Crate these terms will supersede the license and you may use the
 * software solely pursuant to the terms of the relevant commercial
 * agreement.
 */

package io.crate.operation.auth;

import io.crate.operation.user.User;
import io.crate.protocols.postgres.ConnectionProperties;
import io.crate.test.integration.CrateUnitTest;
import org.junit.Test;

import java.util.Collections;

import static org.hamcrest.core.Is.is;

/**
 * Tests authentication methods of user management module
 */
public class AuthenticationMethodTest extends CrateUnitTest {

    @Test
    public void testTrustAuthentication() throws Exception {
        TrustAuthenticationMethod trustAuth = new TrustAuthenticationMethod(userName -> {
            if (userName.equals("crate")) {
                return new User("crate", Collections.emptySet(), Collections.emptySet());
            }
            return null;
        });
        assertThat(trustAuth.name(), is("trust"));

        ConnectionProperties connectionProperties = new ConnectionProperties(null, Protocol.POSTGRES, null);
        assertThat(trustAuth.authenticate("crate", connectionProperties).name(), is("crate"));

        expectedException.expectMessage("trust authentication failed for user \"cr8\"");
        trustAuth.authenticate("cr8", connectionProperties);
    }

    @Test
    public void testAlwaysOKAuthentication() throws Exception {
        AlwaysOKAuthentication alwaysOkAuth = new AlwaysOKAuthentication(userName -> {
            if (userName.equals("crate")) {
                return new User("crate", Collections.emptySet(), Collections.emptySet());
            }
            return null;
        });

        ConnectionProperties connectionProperties = new ConnectionProperties(null, Protocol.POSTGRES, null);
        AuthenticationMethod alwaysOkAuthMethod = alwaysOkAuth.resolveAuthenticationType("crate", connectionProperties);

        assertThat(alwaysOkAuthMethod.name(), is("alwaysOk"));
        assertThat(alwaysOkAuthMethod.authenticate("crate", connectionProperties).name(), is("crate"));

        expectedException.expectMessage("authentication failed for user \"cr8\"");
        alwaysOkAuthMethod.authenticate("cr8", connectionProperties);
    }
}
