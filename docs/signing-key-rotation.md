# Signing key rotation

The config signing key is an RSA key named `prm-config-signing`. Key Vault generates it. It is not a deployment parameter, and the private key is not written into the container environment.

The portal signs each config version, each proposal revision, and each admin audit row with PS256. The active config is the highest verified version. The proxy verifies those documents with the public key. Its role is `keys/read` and `keys/verify/action`. `keys/sign/action` is not included. A verify-only signer refuses `sign`.

The deployer receives a key-create role for setup. That role does not include `keys/sign/action`. Do not assign Key Vault Crypto Officer. If an earlier deployment granted Crypto Officer (`14b46e9e-c2b7-41b4-b545-8d5e335c5e6a`) on the vault, delete that assignment after the key exists.

The proxy tool-call audit log stays a separate HMAC (`PRM_SECRET_AUDIT_HMAC_KEY`). Rotating the config key does not rotate that HMAC.

The session cookie key is the Key Vault secret `session-hmac-key`. The portal creates it on first start when the secret is missing. Production refuses `PRM_ADMIN_SESSION_HMAC_KEY`, `PRM_STORE_HMAC_KEY`, and `PRM_ADMIN_AUDIT_HMAC_KEY`.

## Rotate the signing key

1. Create a new version of `prm-config-signing` in Key Vault. Leave the current version enabled.
2. The portal signs with the latest enabled version, chosen by `attributes.created`, the next time it signs.
3. The proxy loads every enabled version and verifies with the `kid` on the document. Older documents stay valid while that version is enabled.
4. Do not disable a version that is still the `kid` on a retained blob. Blob versioning keeps those bytes. The immutability policy on `prm-config` is created unlocked so a bad policy can still be removed during the soak. Lock it after the soak, as described below. The proxy checks every version file.
5. A replacement document is a new version file signed by the new key. Version files are write-once, so an existing blob is not rewritten.
6. After every retained document verifies under a version that is still enabled, disable the old key version. Do not purge it during the retention window.

Rotation does not reset the version floor. A published `version_id` below the floor still fails closed with `snapshot_replay`.

## If the signing key is compromised

1. Create a new version of `prm-config-signing`. The portal signs with that version.
2. Publish a new config version. That file is signed by the new key. Do not rewrite older version blobs.
3. Raise the version floor to that new `version_id`. The proxy then refuses every older snapshot, including ones the compromised key can still verify.
4. Disable the old key version after the proxy has loaded the new version. A document whose `kid` is disabled fails verification.

## HSM

The default vault is Standard and the key is software RSA 2048. For an HSM-backed key, deploy the portal template with `keyVaultSku` `premium` and `signingKeyBits` `3072`. That key type is `RSA-HSM`. Premium is required for HSM keys. A 3072-bit key on the Standard vault is rejected by the template. Rotation is the same: a new key version, then the floor, then disable the old version.

## Immutability soak

`prm-config` and `prm-floor` are created with an unlocked 365-day immutability policy and protected append writes. Version files are block blobs, so they stay write-once. The audit log and the floor are append blobs, so new lines can be added. Leave the policies unlocked until publishes, proposal decisions, and floor appends have been exercised. Then lock them:

```bash
az storage container immutability-policy lock --account-name <account> --container-name prm-config --auth-mode login
az storage container immutability-policy lock --account-name <account> --container-name prm-floor --auth-mode login
```

A locked policy cannot be removed. The retention period can only increase.

## Junk or unsigned version file

A locked policy keeps every blob for the retention window. A junk or unsigned version file stays in `prm-config`. The proxy logs `alert reason_code=store_signature_invalid` and stays stopped. The scheduled query `prm-store-signature-invalid` on the proxy Log Analytics workspace fires on that line (`ContainerAppConsoleLogs | where Log contains "store_signature_invalid"`).

Recovery is a new container and a re-publish:

1. Create a new config container on the same private account, for example `prm-config-restore`. Leave the locked `prm-config` container in place for the retention window. Leave its blobs there.
2. Create a new floor container, for example `prm-floor-restore`, with the same unlocked 365-day policy and protected append writes. A re-published store starts at version 1. The existing floor still records a higher version, so the proxy would refuse the new store as `snapshot_replay` until the floor is new as well.
3. Grant the portal identity Storage Blob Data Contributor on the new config container only. Grant the proxy identity Storage Blob Data Reader on that container and Storage Blob Data Contributor on the new floor container.
4. Point the portal `PRM_CONFIG_STORE` at the new config container and restart the portal.
5. Re-publish the last known-good config through the portal. The portal signs a new version file with the current key. That file is version 1 in the new container.
6. Point the proxy `PRM_CONFIG_STORE` and `PRM_VERSION_FLOOR` at the new containers and restart the proxy. The proxy verifies the new version and appends the new floor.
7. After the soak on the new containers, lock those policies before a PHI client is enabled. The pre-PHI checklist is below.

While a policy is still unlocked, delete the bad blob and publish the next version in the same container. The steps above are for a policy that is already locked.

## Pre-PHI checklist

Before a PHI client is enabled:

- Lock the immutability policies on `prm-config` and `prm-floor` after the soak. Use the two `az storage container immutability-policy lock` commands above.

## Version floor

`prm-floor` is a separate container. The portal identity is Storage Blob Data Contributor on `prm-config` only. The proxy identity is the writer of `prm-floor` (`floor.jsonl`, an append blob) and a reader of `prm-config`. The floor policy allows protected append writes so new lines can be added. A line that lowers the mark fails closed.

Production and Entra mode require `PRM_VERSION_FLOOR`. A local floor file must sit outside the store directory.

## Session secret

To rotate the session secret, write a new value of at least 32 bytes to `session-hmac-key` and restart the portal. Existing cookies stop verifying. Do not pass the value as a deployment parameter.
