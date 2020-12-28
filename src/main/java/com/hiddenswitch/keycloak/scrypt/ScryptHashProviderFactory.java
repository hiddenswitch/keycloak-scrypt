package com.hiddenswitch.keycloak.scrypt;

import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class ScryptHashProviderFactory implements PasswordHashProviderFactory {

	public static final String ID = "scrypt";
	public static final int DEFAULT_N = 16384;
	public static final int DEFAULT_R = 8;
	public static final int DEFAULT_P = 1;


	@Override
	public PasswordHashProvider create(KeycloakSession session) {
		return new ScryptHashProvider(ID, DEFAULT_N, DEFAULT_R, DEFAULT_P);
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
		return ID;
	}
}
