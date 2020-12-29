package com.hiddenswitch.keycloak.tests;

import com.google.common.collect.ImmutableMap;
import com.hiddenswitch.keycloak.containers.KeycloakWithScryptContainer;
import com.hiddenswitch.keycloak.scrypt.ScryptHashProvider;
import com.lambdaworks.crypto.SCryptUtil;
import org.apache.http.HttpStatus;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.*;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.ws.rs.NotFoundException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.Response;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static java.util.stream.Collectors.toMap;

@Testcontainers
public class BasicTests {

	@Container
	public KeycloakWithScryptContainer keycloak = new KeycloakWithScryptContainer();

	@Test
	public void testHashAlgorithmPolicyLogic() {
		Keycloak adminClient = keycloak();
		String realmId = UUID.randomUUID().toString();
		String clientId = UUID.randomUUID().toString();
		String clientSecret = UUID.randomUUID().toString();

		RealmResource realm = createRealm(adminClient, realmId, clientId, clientSecret);
		RealmRepresentation realmRepresentation = realm.toRepresentation();
		realmRepresentation.setPasswordPolicy("hashAlgorithm(nonexistent)");
		Assertions.assertThrows(Throwable.class, () -> {
			realm.update(realmRepresentation);
		}, "should not be able to add a nonexistent hash algorithm");
	}

	@Test
	public void testScryptAccountCreation() throws IllegalAccessException {
		Keycloak adminClient = keycloak();
		String realmId = UUID.randomUUID().toString();
		String clientId = UUID.randomUUID().toString();
		String clientSecret = UUID.randomUUID().toString();

		RealmResource realm = createRealm(adminClient, realmId, clientId, clientSecret);
		RealmRepresentation realmRepresentation = realm.toRepresentation();
		realmRepresentation.setPasswordPolicy("hashAlgorithm(scrypt)");
		realm.update(realmRepresentation);

		UserRepresentation user = new UserRepresentation();
		user.setEnabled(true);
		String email = UUID.randomUUID().toString() + "@abc.com";
		String username = UUID.randomUUID().toString();
		String password = UUID.randomUUID().toString();
		String hashedPassword = SCryptUtil.scrypt(password, 256, 8, 1);
		user.setEmail(email);
		user.setUsername(username);

		PasswordCredentialModel credentialModel = PasswordCredentialModel.createFromValues(ScryptHashProvider.ID, new byte[0], 1, hashedPassword);
		CredentialRepresentation credential = ModelToRepresentation.toRepresentation(credentialModel);
		credential.setTemporary(false);
		user.setCredentials(Collections.singletonList(credential));
		realm.users().create(user);

		// try to authenticate the user using OAuth2
		Client client = ResteasyClientBuilder.newBuilder().build();
		MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
		formData.put("client_id", Collections.singletonList(clientId));
		formData.put("grant_type", Collections.singletonList("password"));
		formData.put("client_secret", Collections.singletonList(clientSecret));
		formData.put("scope", Collections.singletonList("openid"));
		formData.put("username", Collections.singletonList(username));
		formData.put("password", Collections.singletonList(password));
		Response res = client.target("http://" + keycloak.getContainerIpAddress() + ":" + keycloak.getHttpPort() + "/auth/realms/" + realmId + "/protocol/openid-connect/token")
				.request(MediaType.APPLICATION_FORM_URLENCODED)
				.accept(MediaType.APPLICATION_JSON)
				.post(Entity.form(formData));
		Assertions.assertEquals(HttpStatus.SC_OK, res.getStatus());
		AccessTokenResponse accessToken = res.readEntity(AccessTokenResponse.class);
		res.close();
		Assertions.assertNotNull(accessToken.getToken(), "received a token");
	}

	protected Keycloak keycloak() {
		ResteasyClientBuilder client = (ResteasyClientBuilder) ResteasyClientBuilder.newBuilder();

		return KeycloakBuilder.builder()
				.serverUrl(keycloak.getAuthServerUrl())
				.realm("master")
				.username(keycloak.getAdminUsername())
				.password(keycloak.getAdminPassword())
				.clientId("admin-cli")
				.grantType("password")
				.resteasyClient(client.build())
				.build();
	}

	protected RealmResource createRealm(Keycloak keycloak, String realmId, String clientId, String clientSecret) {
		Optional<RealmRepresentation> existing = Optional.<RealmRepresentation>empty();
		try {
			existing = keycloak.realms().findAll().stream().filter(realm -> realm.getRealm().equals(realmId)).findFirst();
		} catch (NotFoundException ignored) {
		}

		if (existing.isPresent()) {
			return keycloak.realm(realmId);
		}

		// Create a default
		RealmRepresentation realmRepresentation = new RealmRepresentation();
		realmRepresentation.setRealm(realmId);
		realmRepresentation.setDisplayName("");
		realmRepresentation.setSslRequired(SslRequired.EXTERNAL.toString());
		realmRepresentation.setEnabled(true);

		keycloak.realms().create(realmRepresentation);

		RealmResource realm = keycloak.realms().realm(realmId);
		Map<String, String> flows = realm.flows().getFlows()
				.stream().collect(toMap(AuthenticationFlowRepresentation::getAlias, AuthenticationFlowRepresentation::getId));
		ClientRepresentation client = new ClientRepresentation();
		client.setClientId(clientId);
		client.setDirectAccessGrantsEnabled(true);

		// Should now be confidential
		client.setClientAuthenticatorType("client-secret");
		client.setServiceAccountsEnabled(false);
		client.setStandardFlowEnabled(true);
		client.setSecret(clientSecret);
		client.setRedirectUris(Collections.singletonList("/oauth2callback"));
		client.setAuthenticationFlowBindingOverrides(ImmutableMap.of(
				"direct_grant", flows.get("direct grant"),
				"browser", flows.get("browser")
		));

		client.setWebOrigins(Collections.singletonList("+"));
		realm.clients().create(client);
		return realm;
	}
}
