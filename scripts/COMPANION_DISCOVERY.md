# Companion discovery probe

Run `python scripts/companion_discovery.py --home /absolute/profile/home` with an explicitly selected Hermes profile. This optional standalone script imports no plugin or gateway code, reads no provider configuration or pairing keys, creates no files, and starts no processes. Existing plugin registration and update behavior are unchanged.

The response describes on-disk installation evidence only. `metadataPresent` means a canonical source and immutable revision appear in installation metadata; it does not establish installed-byte integrity, Hermes availability, plugin enablement, gateway liveness or activation. `activeRevision` is always null. Live identity must come from the authenticated running gateway. Unknown, malformed or symlinked installations require the existing repair flow.

`prepare_initial_install` is an importable attended-plan helper for an absent plugin. It rechecks the discovery fingerprint and returns pinned arguments for the supported Hermes plugin installer with `--no-enable`. The caller must locate/qualify the actual Hermes executable and explicitly set the selected profile's `HERMES_HOME`. No executable path is inferred or run. The plan is not a signature verifier, installation lock or transaction; the future installer must verify release trust and revalidate state while holding installation ownership. Existing installations always route to Hermes update/repair, without overwriting user changes or introducing a second updater.

Pairing/enablement, gateway restart and activation receipts remain Hermes-owned attended steps. This probe does not change those flows.

Validation: `python -m unittest tests.test_companion_discovery -v`. Tests use temporary profiles; no installed Hermes is required. Full installer/gateway integration remains a separate qualification step.
