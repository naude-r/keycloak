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

package org.keycloak.testsuite.admin.authentication;

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlow;
import org.keycloak.authentication.authenticators.client.ClientIdAndSecretAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationExecutionRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public class ExecutionTest extends AbstractAuthenticationTest {

    @Test
    public void testAddRemoveExecution() {

        // try add execution to built-in flow
        HashMap<String, String> params = new HashMap<>();
        params.put("provider", "idp-review-profile");
        try {
            authMgmtResource.addExecution("browser", params);
            Assert.fail("add execution to built-in flow should fail");
        } catch (BadRequestException expected) {
            // Expected
        }

        // try add execution to not-existent flow
        try {
            authMgmtResource.addExecution("not-existent", params);
            Assert.fail("add execution to not-existent flow should fail");
        } catch (BadRequestException expected) {
            // Expected
        }

        // copy built-in flow so we get a new editable flow
        params.put("newName", "Copy of browser");
        Response response = authMgmtResource.copy("browser", params);
        try {
            Assert.assertEquals("Copy flow", 201, response.getStatus());
        } finally {
            response.close();
        }

        // add execution using inexistent provider
        params.put("provider", "test-execution");
        try {
            authMgmtResource.addExecution("Copy of browser", params);
            Assert.fail("add execution with inexistent provider should fail");
        } catch(BadRequestException expected) {
        }

        // add execution - should succeed
        params.put("provider", "idp-review-profile");
        authMgmtResource.addExecution("Copy of browser", params);

        // check execution was added
        List<AuthenticationExecutionInfoRepresentation> executionReps = authMgmtResource.getExecutions("Copy of browser");
        AuthenticationExecutionInfoRepresentation exec = findExecutionByProvider("idp-review-profile", executionReps);
        Assert.assertNotNull("idp-review-profile added", exec);

        // we'll need auth-cookie later
        AuthenticationExecutionInfoRepresentation authCookieExec = findExecutionByProvider("auth-cookie", executionReps);

        compareExecution(newExecInfo("Review Profile", "idp-review-profile", true, 0, 3, DISABLED, null, new String[]{REQUIRED, DISABLED}), exec);

        // remove execution
        authMgmtResource.removeExecution(exec.getId());

        // check execution was removed
        executionReps = authMgmtResource.getExecutions("Copy of browser");
        exec = findExecutionByProvider("idp-review-profile", executionReps);
        Assert.assertNull("idp-review-profile removed", exec);

        // now add the execution again using a different method and representation

        // delete auth-cookie
        authMgmtResource.removeExecution(authCookieExec.getId());

        AuthenticationExecutionRepresentation rep = new AuthenticationExecutionRepresentation();
        rep.setPriority(10);
        rep.setAuthenticator("auth-cookie");
        rep.setRequirement(OPTIONAL);

        // Should fail - missing parent flow
        response = authMgmtResource.addExecution(rep);
        try {
            Assert.assertEquals("added execution missing parent flow", 400, response.getStatus());
        } finally {
            response.close();
        }

        // Should fail - not existent parent flow
        rep.setParentFlow("not-existent-id");
        response = authMgmtResource.addExecution(rep);
        try {
            Assert.assertEquals("added execution missing parent flow", 400, response.getStatus());
        } finally {
            response.close();
        }

        // Should fail - add execution to builtin flow
        AuthenticationFlowRepresentation browserFlow = findFlowByAlias("browser", authMgmtResource.getFlows());
        rep.setParentFlow(browserFlow.getId());
        response = authMgmtResource.addExecution(rep);
        try {
            Assert.assertEquals("added execution to builtin flow", 400, response.getStatus());
        } finally {
            response.close();
        }

        // get Copy of browser flow id, and set it on execution
        List<AuthenticationFlowRepresentation> flows = authMgmtResource.getFlows();
        AuthenticationFlowRepresentation flow = findFlowByAlias("Copy of browser", flows);
        rep.setParentFlow(flow.getId());

        // add execution - should succeed
        response = authMgmtResource.addExecution(rep);
        try {
            Assert.assertEquals("added execution", 201, response.getStatus());
        } finally {
            response.close();
        }

        // check execution was added
        List<AuthenticationExecutionInfoRepresentation> executions = authMgmtResource.getExecutions("Copy of browser");
        exec = findExecutionByProvider("auth-cookie", executions);
        Assert.assertNotNull("auth-cookie added", exec);

        // Note: there is no checking in addExecution if requirement is one of requirementChoices
        // Thus we can have OPTIONAL which is neither ALTERNATIVE, nor DISABLED
        compareExecution(newExecInfo("Cookie", "auth-cookie", false, 0, 2, OPTIONAL, null, new String[]{ALTERNATIVE, DISABLED}), exec);
    }

    @Test
    public void testUpdateExecution() {

        // get current auth-cookie execution
        List<AuthenticationExecutionInfoRepresentation> executionReps = authMgmtResource.getExecutions("browser");
        AuthenticationExecutionInfoRepresentation exec = findExecutionByProvider("auth-cookie", executionReps);

        Assert.assertEquals("auth-cookie set to ALTERNATIVE", ALTERNATIVE, exec.getRequirement());

        // switch from DISABLED to ALTERNATIVE
        exec.setRequirement(DISABLED);
        authMgmtResource.updateExecutions("browser", exec);

        // make sure the change is visible
        executionReps = authMgmtResource.getExecutions("browser");

        // get current auth-cookie execution
        AuthenticationExecutionInfoRepresentation exec2 = findExecutionByProvider("auth-cookie", executionReps);
        compareExecution(exec, exec2);
    }

    @Test
    public void testClientFlowExecutions() {
        // Create client flow
        AuthenticationFlowRepresentation clientFlow = newFlow("new-client-flow", "desc", AuthenticationFlow.CLIENT_FLOW, true, false);
        Response response = authMgmtResource.createFlow(clientFlow);
        Assert.assertEquals(201, response.getStatus());
        response.close();

        // Add execution to it
        Map<String, String> executionData = new HashMap<>();
        executionData.put("provider", ClientIdAndSecretAuthenticator.PROVIDER_ID);
        authMgmtResource.addExecution("new-client-flow", executionData);

        // Check executions of not-existent flow - SHOULD FAIL
        try {
            authMgmtResource.getExecutions("not-existent");
            Assert.fail("Not expected to find executions");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // Check existent executions
        List<AuthenticationExecutionInfoRepresentation> executions = authMgmtResource.getExecutions("new-client-flow");
        AuthenticationExecutionInfoRepresentation executionRep = findExecutionByProvider(ClientIdAndSecretAuthenticator.PROVIDER_ID, executions);
        Assert.assertNotNull(executionRep);

        // Update execution with not-existent flow - SHOULD FAIL
        try {
            authMgmtResource.updateExecutions("not-existent", executionRep);
            Assert.fail("Not expected to update execution with not-existent flow");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // Update execution with not-existent ID - SHOULD FAIL
        try {
            AuthenticationExecutionInfoRepresentation executionRep2 = new AuthenticationExecutionInfoRepresentation();
            executionRep2.setId("not-existent");
            authMgmtResource.updateExecutions("new-client-flow", executionRep2);
            Assert.fail("Not expected to update not-existent execution");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // Update success
        executionRep.setRequirement(ALTERNATIVE);
        authMgmtResource.updateExecutions("new-client-flow", executionRep);

        // Check updated
        executionRep = findExecutionByProvider(ClientIdAndSecretAuthenticator.PROVIDER_ID, authMgmtResource.getExecutions("new-client-flow"));
        Assert.assertEquals(ALTERNATIVE, executionRep.getRequirement());

        // Remove execution with not-existent ID
        try {
            authMgmtResource.removeExecution("not-existent");
            Assert.fail("Didn't expect to find execution");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // Successfuly remove execution and flow
        authMgmtResource.removeExecution(executionRep.getId());
        AuthenticationFlowRepresentation rep = findFlowByAlias("new-client-flow", authMgmtResource.getFlows());
        authMgmtResource.deleteFlow(rep.getId());
    }
}
