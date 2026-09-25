package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-networkfirewall-tls-ca-max-one", "ERROR", name,
	"Properties.TLSInspectionConfiguration.ServerCertificateConfigurations",
	sprintf("this TLS inspection configuration carries %d ServerCertificateConfigurations; CreateTLSInspectionConfiguration answers \"Exactly one ServerCertificateConfiguration must be set\"", [count(cfgs)]),
	"Fold the inbound certificates and the outbound CertificateAuthorityArn into a single ServerCertificateConfiguration",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::TLSInspectionConfiguration")
	cfgs := _pf_nfwlib_tls_configs(name)
	_pf_countable_items(cfgs)
	count(cfgs) > 1
}
