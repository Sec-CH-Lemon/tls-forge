package fingerprint

import "fmt"

// Human names for the values a fingerprint is built from.
//
// A diff that reads
//
//	signature_algorithms  browser has mldsa44, we do not
//
// is actionable; one that reads `0x0904` sends the reader to a registry. The
// tables cover what browsers actually send — anything else falls back to hex,
// which is still correct, just less kind.

var extensionNames = map[uint16]string{
	0:     "server_name",
	5:     "status_request",
	10:    "supported_groups",
	11:    "ec_point_formats",
	13:    "signature_algorithms",
	16:    "alpn",
	17:    "status_request_v2",
	18:    "signed_certificate_timestamp",
	21:    "padding",
	22:    "encrypt_then_mac",
	23:    "extended_master_secret",
	27:    "compress_certificate",
	28:    "record_size_limit",
	34:    "delegated_credentials",
	35:    "session_ticket",
	41:    "pre_shared_key",
	42:    "early_data",
	43:    "supported_versions",
	44:    "cookie",
	45:    "psk_key_exchange_modes",
	49:    "post_handshake_auth",
	50:    "signature_algorithms_cert",
	51:    "key_share",
	17513: "application_settings",
	17613: "application_settings_old",
	30031: "channel_id",
	51764: "trust_anchors",
	65037: "encrypted_client_hello",
	65281: "renegotiation_info",
}

var groupNames = map[uint16]string{
	23:    "P-256",
	24:    "P-384",
	25:    "P-521",
	29:    "X25519",
	30:    "X448",
	256:   "ffdhe2048",
	257:   "ffdhe3072",
	4587:  "SecP256r1MLKEM768",
	4588:  "X25519MLKEM768",
	25497: "X25519Kyber768Draft00",
}

var signatureNames = map[uint16]string{
	0x0201: "rsa_pkcs1_sha1",
	0x0203: "ecdsa_sha1",
	0x0401: "rsa_pkcs1_sha256",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0501: "rsa_pkcs1_sha384",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0601: "rsa_pkcs1_sha512",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
	0x0809: "rsa_pss_pss_sha256",
	0x080a: "rsa_pss_pss_sha384",
	0x080b: "rsa_pss_pss_sha512",
	// The post-quantum signature schemes current Chrome advertises ahead of the
	// classical set. Their absence was, for a long time, the only thing
	// separating a stock tls-client handshake from the real browser's.
	0x0904: "mldsa44",
	0x0905: "mldsa65",
	0x0906: "mldsa87",
}

var cipherNames = map[uint16]string{
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

var versionNames = map[uint16]string{
	0x0300: "SSL 3.0",
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
	0x0303: "TLS 1.2",
	0x0304: "TLS 1.3",
}

var settingNames = map[uint16]string{
	1: "HEADER_TABLE_SIZE",
	2: "ENABLE_PUSH",
	3: "MAX_CONCURRENT_STREAMS",
	4: "INITIAL_WINDOW_SIZE",
	5: "MAX_FRAME_SIZE",
	6: "MAX_HEADER_LIST_SIZE",
	8: "ENABLE_CONNECT_PROTOCOL",
	9: "NO_RFC7540_PRIORITIES",
}

// ExtensionName names a TLS extension, GREASE included.
func ExtensionName(v uint16) string { return lookup(extensionNames, v) }

// GroupName names a supported group (named curve).
func GroupName(v uint16) string { return lookup(groupNames, v) }

// SignatureName names a signature scheme.
func SignatureName(v uint16) string { return lookup(signatureNames, v) }

// CipherName names a cipher suite.
func CipherName(v uint16) string { return lookup(cipherNames, v) }

// VersionName names a TLS version.
func VersionName(v uint16) string { return lookup(versionNames, v) }

// SettingName names an HTTP/2 setting.
func SettingName(v uint16) string { return lookup(settingNames, v) }

func lookup(table map[uint16]string, v uint16) string {
	if IsGREASE(v) {
		return fmt.Sprintf("GREASE(0x%04x)", v)
	}
	if name, ok := table[v]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", v)
}

func namesOf(values []uint16, name func(uint16) string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = name(v)
	}
	return out
}
