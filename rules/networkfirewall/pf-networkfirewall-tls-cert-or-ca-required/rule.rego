package cdk_preflight

import rego.v1

_pf_nfwtls_has_certs(cfg) if {
	c := object.get(cfg, "ServerCertificates", [])
	is_array(c)
	count(c) > 0
}

# An intrinsic in place of the list is not proof of absence.
_pf_nfwtls_has_certs(cfg) if {
	not is_array(object.get(cfg, "ServerCertificates", []))
}

violation contains make_diag_full("pf-networkfirewall-tls-cert-or-ca-required", "ERROR", name,
	sprintf("Properties.TLSInspectionConfiguration.ServerCertificateConfigurations[%d]", [i]),
	"this ServerCertificateConfiguration has neither ServerCertificates nor a CertificateAuthorityArn; CreateTLSInspectionConfiguration answers \"ServerCertificates or CertificateAuthorityArn is required. You can specify either, or both.\"",
	"Add ServerCertificates for inbound inspection, a CertificateAuthorityArn for outbound inspection, or both",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_ServerCertificateConfiguration.html") if {
	some [name, i, cfg] in _pf_nfwlib_tls_config
	not _pf_nfwtls_has_certs(cfg)
	object.get(cfg, "CertificateAuthorityArn", null) == null
}
