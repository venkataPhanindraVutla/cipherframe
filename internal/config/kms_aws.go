package config

// KMSAWS holds the AWS KMS provider settings (M2-2). It is empty until that provider's task fills it.
// Secrets must use Secret or Credential so they stay redacted.
type KMSAWS struct{}

// kmsAWS reads the AWS KMS settings. It runs only when CIPHERFRAME_KMS_PROVIDER names this provider.
func (*loader) kmsAWS(_ bool) KMSAWS {
	return KMSAWS{}
}
