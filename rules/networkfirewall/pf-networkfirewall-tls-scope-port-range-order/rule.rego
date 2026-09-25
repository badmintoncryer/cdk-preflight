package cdk_preflight

import rego.v1

# Every literal port range of every TLS inspection scope, as
# [resource, config index, scope index, property, range index, FromPort, ToPort].
_pf_nfwtls_port_range contains [name, ci, si, key, pi, f, t] if {
	some [name, ci, si, sc] in _pf_nfwlib_tls_scope
	some key in {"SourcePorts", "DestinationPorts"}
	ranges := object.get(sc, key, null)
	is_array(ranges)
	some pi, pr in ranges
	is_object(pr)
	f := object.get(pr, "FromPort", null)
	t := object.get(pr, "ToPort", null)
	is_number(f)
	is_number(t)
}

violation contains make_diag_full("pf-networkfirewall-tls-scope-port-range-order", "ERROR", name,
	sprintf("Properties.TLSInspectionConfiguration.ServerCertificateConfigurations[%d].Scopes[%d].%s[%d]", [ci, si, key, pi]),
	sprintf("FromPort %v is above ToPort %v; CreateTLSInspectionConfiguration answers \"FromPort, ToPort is not within the bound, parameter: [%v, %v]\"", [f, t, f, t]),
	"Put the lower port in FromPort",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_PortRange.html") if {
	some [name, ci, si, key, pi, f, t] in _pf_nfwtls_port_range
	f > t
}
