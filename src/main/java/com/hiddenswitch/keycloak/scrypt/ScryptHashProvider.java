package com.hiddenswitch.keycloak.scrypt;

import com.lambdaworks.crypto.SCryptUtil;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

public class ScryptHashProvider implements PasswordHashProvider {
	private final String id;
	private final int n;
	private final int r;
	private final int p;

	public ScryptHashProvider(String id, int n, int r, int p) {
		this.id = id;
		this.n = n;
		this.r = r;
		this.p = p;
	}

	@Override
	public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
		return id.equals(credential.getPasswordCredentialData().getAlgorithm());
	}

	@Override
	public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
		return PasswordCredentialModel.createFromValues(id, new byte[0], iterations, encode(rawPassword, iterations));
	}

	@Override
	public String encode(String rawPassword, int iterations) {
		return SCryptUtil.scrypt(rawPassword, n, r, p);
	}

	@Override
	public boolean verify(String rawPassword, PasswordCredentialModel credential) {
		return SCryptUtil.check(rawPassword, credential.getPasswordSecretData().getValue());
	}

	@Override
	public void close() {
	}
}
