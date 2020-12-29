# keycloak-scrypt

A tested password hash provider using Scrypt for Keycloak. Tested for version 12.0.1.

### How is this tested

You must have `docker` installed to integration test this JAR.

```shell
gradle test
```

A keycloak docker image is built on the fly with the output of `gradle shadowJar` (a JAR file built at `shadowJar.archiveFile.get().asFile.absolutePath`, typically `build/libs/keycloak-scrypt.jar`). That JAR is copied to `/opt/jboss/keycloak/standalone/deployments/` inside the container.

This can be used as a template for all Keycloak extensions.

### How do I install this into Keycloak?

Add the output of `gradle shadowJar` (typically `build/libs/keycloak-scrypt.jar`) to `/opt/jboss/keycloak/standalone/deployments/` inside the container.

### How can I use this to use Scrypt for my passwords and migrate accounts using Scrypt passwords?

 1. Add the appropriate Keycloak dependencies. You need the SPIs to correctly encode the password for account creation:

    ```groovy
    def keycloakVersion = "12.0.1"
    implementation(group: 'org.keycloak', name: 'keycloak-admin-client', version: "$keycloakVersion")
    implementation "org.keycloak:keycloak-server-spi:$keycloakVersion"
    implementation "org.keycloak:keycloak-server-spi-private:$keycloakVersion"
    implementation platform("org.keycloak.bom:keycloak-bom-parent:$keycloakVersion")
    ```
 2. Create a Keycloak admin client.
 3. Update your realm to support `scrypt` as a password algorithm. This will also make all further passwords encoded in Scrypt when user accounts are created in this realm.
    ```java
    // Retrieve your realm from the keycloak admin client
    RealmResource realm = ...
    RealmRepresentation realmRepresentation = realm.toRepresentation();
    realmRepresentation.setPasswordPolicy("hashAlgorithm(scrypt)");
    realm.update(realmRepresentation);
    ```
 4. Create a user with the Server SPI representation of credentials. For example:
    ```java
    UserRepresentation user = new UserRepresentation();
    user.setEnabled(true);
    String email = UUID.randomUUID().toString() + "@abc.com";
    String username = UUID.randomUUID().toString();
    String password = UUID.randomUUID().toString();
    String hashedPassword = SCryptUtil.scrypt(password, 16384, 8, 1);
    user.setEmail(email);
    user.setUsername(username);
    PasswordCredentialModel credentialModel = PasswordCredentialModel.createFromValues(ScryptHashProvider.ID, new byte[0], 1, hashedPassword);
    CredentialRepresentation credential = ModelToRepresentation.toRepresentation(credentialModel);
    credential.setTemporary(false);
    user.setCredentials(Collections.singletonList(credential));
    realm.users().create(user);
    ```

Observe iterations are not used. The hash parameters for this package are N = 16384, R = 8, p = 1.