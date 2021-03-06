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

package org.keycloak.services.resources.admin;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.NotFoundException;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.ScopeContainerModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ScopeMappedClientResource {
    protected RealmModel realm;
    private RealmAuth auth;
    protected ScopeContainerModel scopeContainer;
    protected KeycloakSession session;
    protected ClientModel scopedClient;
    protected AdminEventBuilder adminEvent;
    
    public ScopeMappedClientResource(RealmModel realm, RealmAuth auth, ScopeContainerModel scopeContainer, KeycloakSession session, ClientModel scopedClient, AdminEventBuilder adminEvent) {
        this.realm = realm;
        this.auth = auth;
        this.scopeContainer = scopeContainer;
        this.session = session;
        this.scopedClient = scopedClient;
        this.adminEvent = adminEvent;
    }

    /**
     * Get the roles associated with a client's scope
     *
     * Returns roles for the client.
     *
     * @return
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getClientScopeMappings() {
        auth.requireView();

        Set<RoleModel> mappings = KeycloakModelUtils.getClientScopeMappings(scopedClient, scopeContainer); //scopedClient.getClientScopeMappings(client);
        List<RoleRepresentation> mapRep = new ArrayList<RoleRepresentation>();
        for (RoleModel roleModel : mappings) {
            mapRep.add(ModelToRepresentation.toRepresentation(roleModel));
        }
        return mapRep;
    }

    /**
     * The available client-level roles
     *
     * Returns the roles for the client that can be associated with the client's scope
     *
     * @return
     */
    @Path("available")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getAvailableClientScopeMappings() {
        auth.requireView();

        Set<RoleModel> roles = scopedClient.getRoles();
        return ScopeMappedResource.getAvailable(scopeContainer, roles);
    }

    /**
     * Get effective client roles
     *
     * Returns the roles for the client that are associated with the client's scope.
     *
     * @return
     */
    @Path("composite")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getCompositeClientScopeMappings() {
        auth.requireView();

        Set<RoleModel> roles = scopedClient.getRoles();
        return ScopeMappedResource.getComposite(scopeContainer, roles);
    }

    /**
     * Add client-level roles to the client's scope
     *
     * @param roles
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void addClientScopeMapping(List<RoleRepresentation> roles) {
        auth.requireManage();

        for (RoleRepresentation role : roles) {
            RoleModel roleModel = scopedClient.getRole(role.getName());
            if (roleModel == null) {
                throw new NotFoundException("Role not found");
            }
            scopeContainer.addScopeMapping(roleModel);
            adminEvent.operation(OperationType.CREATE).resourcePath(session.getContext().getUri(), roleModel.getId()).representation(roles).success();
        }
    }

    /**
     * Remove client-level roles from the client's scope.
     *
     * @param roles
     */
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    public void deleteClientScopeMapping(List<RoleRepresentation> roles) {
        auth.requireManage();

        if (roles == null) {
            Set<RoleModel> roleModels = KeycloakModelUtils.getClientScopeMappings(scopedClient, scopeContainer);//scopedClient.getClientScopeMappings(client);
            for (RoleModel roleModel : roleModels) {
                scopeContainer.deleteScopeMapping(roleModel);
            }
            adminEvent.operation(OperationType.DELETE).resourcePath(session.getContext().getUri()).representation(roles).success();
        } else {
            for (RoleRepresentation role : roles) {
                RoleModel roleModel = scopedClient.getRole(role.getName());
                if (roleModel == null) {
                    throw new NotFoundException("Role not found");
                }
                scopeContainer.deleteScopeMapping(roleModel);
                adminEvent.operation(OperationType.DELETE).resourcePath(session.getContext().getUri(), roleModel.getId()).representation(roles).success();
            }
        }
    }
}
