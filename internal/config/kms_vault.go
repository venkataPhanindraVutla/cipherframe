package config

// KMSVault holds the Vault Transit provider settings (M2-2). It is empty until that provider's task fills it.
// Secrets must use Secret or Credential so they stay redacted.
type KMSVault struct{}

// kmsVault reads the Vault Transit settings. It runs only when CIPHERFRAME_KMS_PROVIDER names this provider.
func (*loader) kmsVault(_ bool) KMSVault {
	return KMSVault{}
}
