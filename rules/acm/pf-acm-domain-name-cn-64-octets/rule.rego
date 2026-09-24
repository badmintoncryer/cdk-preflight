package cdk_preflight

import rego.v1

# DomainName は証明書のコモンネームになるので X.509 の CN 上限 64 に縛られる。
# スキーマは 253 まで通す（SubjectAlternativeNames はこの上限を受けない）。
violation contains make_diag_full("pf-acm-domain-name-cn-64-octets", "ERROR", name,
	"Properties.DomainName",
	sprintf("DomainName is %d characters; the certificate request fails with \"The first domain name can be no longer than 64 characters.\"", [count(dn)]),
	"Use a DomainName of at most 64 characters and move the longer names to SubjectAlternativeNames",
	"https://docs.aws.amazon.com/acm/latest/APIReference/API_RequestCertificate.html") if {
	some name in resources_of_type("AWS::CertificateManager::Certificate")
	dn := resolve(name, "Properties.DomainName")
	_pf_acm_lit(dn)
	count(dn) > 64
}
