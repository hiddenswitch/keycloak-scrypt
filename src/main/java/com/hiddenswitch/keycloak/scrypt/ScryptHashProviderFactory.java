package com.hiddenswitch.keycloak.scrypt;

import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class ScryptHashProviderFactory implements PasswordHashProviderFactory {


	@Override
	public PasswordHashProvider create(KeycloakSession session) {
		return new ScryptHashProvider(ScryptHashProvider.ID, ScryptHashProvider.DEFAULT_N, ScryptHashProvider.DEFAULT_R, ScryptHashProvider.DEFAULT_P);
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {

	}

	@Override
	public void close() {

	}

	@Override
	public String getId() {
		return ScryptHashProvider.ID;
	}
}
