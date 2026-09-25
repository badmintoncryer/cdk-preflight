package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-networkfirewall-tls-revocation-requires-ca", "ERROR", name,
	sprintf("Properties.TLSInspectionConfiguration.ServerCertificateConfigurations[%d].CheckCertificateRevocationStatus", [i]),
	"revocation checking belongs to outbound inspection, so CreateTLSInspectionConfiguration answers \"CertificateAuthorityArn is required when enabling CheckCertificateRevocationStatus.\"",
	"Add the CertificateAuthorityArn of the CA that signs the outbound certificates, or drop CheckCertificateRevocationStatus",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_ServerCertificateConfiguration.html") if {
	some [name, i, cfg] in _pf_nfwlib_tls_config
	object.get(cfg, "CheckCertificateRevocationStatus", null) != null
	object.get(cfg, "CertificateAuthorityArn", null) == null
}
