package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-networkfirewall-tls-scope-protocol-tcp", "ERROR", name,
	sprintf("Properties.TLSInspectionConfiguration.ServerCertificateConfigurations[%d].Scopes[%d].Protocols", [ci, si]),
	sprintf("TLS runs over TCP, so protocol %v is not something this scope can decrypt; CreateTLSInspectionConfiguration answers \"Protocols is unsupported, parameter: [%v]\"", [p, p]),
	"Set Protocols to [6]",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_ServerCertificateScope.html") if {
	some [name, ci, si, sc] in _pf_nfwlib_tls_scope
	protos := object.get(sc, "Protocols", null)
	is_array(protos)
	some p in protos
	is_number(p)
	p != 6
}
