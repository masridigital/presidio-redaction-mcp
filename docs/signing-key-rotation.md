# Signing key rotation

The config signing key is an RSA key named `prm-config-signing`. Key Vault generates it. It is not a deployment parameter, and the private key is not written into the container environment.

The portal signs each config version, each proposal, the active pointer, and each admin audit row with PS256. The proxy verifies those documents with the public key. Its role is `keys/read` and `keys/verify/action`. `keys/sign/action` is not included. A verify-only signer refuses `sign`.

The proxy tool-call audit log stays a separate HMAC (`PRM_SECRET_AUDIT_HMAC_KEY`). Rotating the config key does not rotate that HMAC.

The session cookie key is the Key Vault secret `session-hmac-key`. The portal creates it on first start when the secret is missing. Production refuses `PRM_ADMIN_SESSION_HMAC_KEY`, `PRM_STORE_HMAC_KEY`, and `PRM_ADMIN_AUDIT_HMAC_KEY`.

## Rotate the signing key

1. Create a new version of `prm-config-signing` in Key Vault. Leave the current version enabled.
2. The portal signs with the latest enabled version, chosen by `attributes.created`, the next time it signs.
3. The proxy loads every enabled version and verifies with the `kid` on the document. Older documents stay valid while that version is enabled.
4. Do not disable a version that is still the `kid` on a retained blob. Blob versioning keeps those bytes, and the immutability policy on `prm-config` keeps them for 365 days. The proxy checks every version file.
5. A replacement document is a new blob version signed by the new key. The config container does not allow protected append writes, so the bytes of an existing blob version stay put.
6. After every retained document verifies under a version that is still enabled, disable the old key version. Do not purge it during the retention window.

Rotation does not reset the version floor. A published `version_id` below the floor still fails closed with `snapshot_replay`.

## Version floor

`prm-floor` is a separate container. The portal identity is Storage Blob Data Contributor on `prm-config` only. The proxy identity is the writer of `prm-floor` (`floor.jsonl`, an append blob) and a reader of `prm-config`. The floor policy allows protected append writes so new lines can be added. A line that lowers the mark fails closed.

Production and Entra mode require `PRM_VERSION_FLOOR`. A local floor file must sit outside the store directory.

## Session secret

To rotate the session secret, write a new value of at least 32 bytes to `session-hmac-key` and restart the portal. Existing cookies stop verifying. Do not pass the value as a deployment parameter.
