package config

// KMSGCP holds the GCP Cloud KMS provider settings (M2-2). It is empty until that provider's task fills it.
// Secrets must use Secret or Credential so they stay redacted.
type KMSGCP struct{}

// kmsGCP reads the GCP Cloud KMS settings. It runs only when CIPHERFRAME_KMS_PROVIDER names this provider.
func (*loader) kmsGCP(_ bool) KMSGCP {
	return KMSGCP{}
}
