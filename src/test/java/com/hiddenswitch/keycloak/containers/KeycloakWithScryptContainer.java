package com.hiddenswitch.keycloak.containers;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;

import java.nio.file.FileSystems;
import java.time.Duration;

public class KeycloakWithScryptContainer extends GenericContainer<KeycloakWithScryptContainer> {
	private static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak";

	private static final int KEYCLOAK_PORT_HTTP = 8080;

	private static final String KEYCLOAK_ADMIN_USER = "admin";
	private static final String KEYCLOAK_ADMIN_PASSWORD = "password";
	private static final String KEYCLOAK_AUTH_PATH = "/auth";

	private String adminUsername = KEYCLOAK_ADMIN_USER;
	private String adminPassword = KEYCLOAK_ADMIN_PASSWORD;
	private String scryptArtifactPath;

	public KeycloakWithScryptContainer() {
		super(KEYCLOAK_IMAGE);
		setImage(new ImageFromDockerfile()
				.withFileFromPath("scrypt.jar", FileSystems.getDefault().getPath(getScryptArtifactPath()))
				.withDockerfileFromBuilder(builder -> {
			builder.from(KEYCLOAK_IMAGE + ":" + getKeycloakVersion());
			builder.copy("scrypt.jar", "/opt/jboss/keycloak/standalone/deployments/");
		}));
		withExposedPorts(KEYCLOAK_PORT_HTTP);
		withEnv("LANGUAGE", "en_US.UTF-8");
		withEnv("LANG", "en_US.UTF-8");
		withEnv("LC_ALL", "en_US.UTF-8");
		withReuse(false);
		setWaitStrategy(Wait
				.forHttp(KEYCLOAK_AUTH_PATH)
				.forPort(KEYCLOAK_PORT_HTTP)
				.withStartupTimeout(Duration.ofSeconds(60))
		);
	}

	@Override
	protected void configure() {
		withCommand(
				"-c standalone.xml", // don't start infinispan cluster
				"-Dkeycloak.profile.feature.upload_scripts=enabled" // enable script uploads
		);

		withEnv("KEYCLOAK_USER", adminUsername);
		withEnv("KEYCLOAK_PASSWORD", adminPassword);
		withEnv("DB_SCHEMA", "keycloak");
	}

	public KeycloakWithScryptContainer withAdminUsername(String adminUsername) {
		this.adminUsername = adminUsername;
		return self();
	}

	public KeycloakWithScryptContainer withAdminPassword(String adminPassword) {
		this.adminPassword = adminPassword;
		return self();
	}

	public KeycloakWithScryptContainer withScryptArtifactPath(String path) {
		this.scryptArtifactPath = path;
		return self();
	}

	public String getScryptArtifactPath() {
		return System.getProperty("com.hiddenswitch.keycloak.test.artifact.path", scryptArtifactPath);
	}

	public String getAuthServerUrl() {
		return String.format("http%s://%s:%s%s", "", getContainerIpAddress(), getMappedPort(KEYCLOAK_PORT_HTTP), KEYCLOAK_AUTH_PATH);
	}

	public KeycloakWithScryptContainer withPostgres(String postgresHostPort, String databaseName, String username, String password) {
		withEnv("DB_VENDOR", "postgres");
		withEnv("DB_ADDR", postgresHostPort);
		withEnv("DB_USER", username);
		withEnv("DB_PASSWORD", password);
		withEnv("DB_DATABASE", databaseName);
		return self();
	}

	public String getAdminUsername() {
		return adminUsername;
	}

	public String getAdminPassword() {
		return adminPassword;
	}

	public int getHttpPort() {
		return getMappedPort(KEYCLOAK_PORT_HTTP);
	}

	protected String getKeycloakVersion() {
		return System.getProperty("com.hiddenswitch.keycloak.test.keycloak.version", "12.0.1");
	}

	private boolean isNotBlank(String s) {
		return s != null && !s.trim().isEmpty();
	}
}
