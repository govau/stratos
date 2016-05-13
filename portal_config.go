package main

type portalConfig struct {
	HTTPClientTimeout   int64    `ucp:"HTTP_CLIENT_TIMEOUT"`
	SkipTLSVerification bool     `ucp:"SKIP_TLS_VERIFICATION"`
	TLSAddress          string   `ucp:"TLS_ADDRESS"`
	TLSCert             string   `ucp:"CERT"`
	TLSCertKey          string   `ucp:"CERT_KEY"`
	ConsoleClient       string   `ucp:"CONSOLE_CLIENT"`
	ConsoleClientSecret string   `ucp:"CONSOLE_CLIENT_SECRET"`
	HCFClient           string   `ucp:"HCF_CLIENT"`
	HCFClientSecret     string   `ucp:"HCF_CLIENT_SECRET"`
	UAAEndpoint         string   `ucp:"UAA_ENDPOINT"`
	AllowedOrigins      []string `ucp:"ALLOWED_ORIGINS"`
	CookieStoreSecret   string   `ucp:"COOKIE_STORE_SECRET"`
}
