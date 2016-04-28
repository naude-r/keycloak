/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.epiuse.advance.hash;

import org.keycloak.Config;
import org.keycloak.common.util.Base64;
import org.keycloak.hash.PasswordHashProvider;
import org.keycloak.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserCredentialValueModel;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Constants;
import de.mkammerer.argon2.Argon2Factory;

/**
 * @author <a href="mailto:roelof.naude@epiuse.com">Roelof Naude</a>
 */
public class Argon2dPasswordHashProvider implements PasswordHashProviderFactory, PasswordHashProvider {

    public static final String ID = "argon2d";

    public UserCredentialValueModel encode(final String rawPassword, final PasswordPolicy policy) {
        int saltLen = Math.max(8, policy.getPasswordSaltLength());
        int iterations = Math.max(20, policy.getHashIterations());
        int memCost = Math.max(65536, policy.getHashMemoryCost());
        int parallelism = Math.max(2, policy.getHashParallelism());
        final Argon2 argon = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2d, saltLen, Argon2Constants.DEFAULT_HASH_LENGTH);
        String encodedPassword = argon.hash(iterations, memCost, parallelism, rawPassword);

        final UserCredentialValueModel credentials = new UserCredentialValueModel();
        credentials.setAlgorithm(ID);
        credentials.setType(UserCredentialModel.PASSWORD);
        credentials.setSalt(null);
        credentials.setHashIterations(iterations);
        credentials.setValue(encodedPassword);
        return credentials;
    }

    public boolean verify(String rawPassword, UserCredentialValueModel credential) {
        final Argon2 argon = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2d);
        return argon.verify(credential.getValue(), rawPassword);
    }

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }

    private String encode(String rawPassword, int iterations, byte[] salt) {
        return null;
    }
}
