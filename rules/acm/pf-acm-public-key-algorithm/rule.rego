package cdk_preflight

import rego.v1

# ACM が公開証明書として発行できるのは 3 つのアルゴリズムだけ。スキーマの enum は
# 7 値（RSA_1024 / RSA_3072 / RSA_4096 / EC_secp521r1 を含む）を通す。残りは
# Private CA からインポートする証明書のためにある。
_pf_acmpka_public := {"RSA_2048", "EC_prime256v1", "EC_secp384r1"}

violation contains make_diag_full("pf-acm-public-key-algorithm", "ERROR", name,
	"Properties.KeyAlgorithm",
	sprintf("KeyAlgorithm '%v' cannot be issued by ACM; the certificate request fails with \"Encryption Algorithm %v is not supported\"", [alg, alg]),
	"Use RSA_2048, EC_prime256v1 or EC_secp384r1 for a public certificate",
	"https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-public.html") if {
	some name in resources_of_type("AWS::CertificateManager::Certificate")
	not _pf_acm_private_ca(name)
	alg := resolve(name, "Properties.KeyAlgorithm")
	_pf_acm_lit(alg)
	not alg in _pf_acmpka_public
}
