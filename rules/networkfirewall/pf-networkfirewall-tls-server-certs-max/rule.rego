package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-networkfirewall-tls-server-certs-max", "ERROR", name,
	sprintf("Properties.TLSInspectionConfiguration.ServerCertificateConfigurations[%d].ServerCertificates", [i]),
	sprintf("this TLS inspection configuration names %d server certificates; the unchangeable quota is 10 and CreateTLSInspectionConfiguration answers \"Certificates limit exceeded\"", [count(certs)]),
	"Keep at most 10 ServerCertificates; a SAN certificate covers more names in one entry",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html") if {
	some [name, i, cfg] in _pf_nfwlib_tls_config
	certs := object.get(cfg, "ServerCertificates", [])
	_pf_countable_items(certs)
	count(certs) > 10
}
