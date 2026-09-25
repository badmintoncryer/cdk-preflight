package cdk_preflight

import rego.v1

_pf_nfwtls_scopes(cfg) := s if {
	s := object.get(cfg, "Scopes", [])
	is_array(s)
}

# An intrinsic in place of the list is not proof of absence.
_pf_nfwtls_scopes(cfg) := ["__pf_opaque"] if {
	not is_array(object.get(cfg, "Scopes", []))
}

# Sources and Destinations of one scope together; a scope needs at least one.
_pf_nfwtls_addresses(sc) := array.concat(_pf_nfwtls_addrs(sc, "Sources"), _pf_nfwtls_addrs(sc, "Destinations"))

_pf_nfwtls_addrs(sc, key) := a if {
	a := object.get(sc, key, [])
	is_array(a)
}

_pf_nfwtls_addrs(sc, key) := ["__pf_opaque"] if {
	not is_array(object.get(sc, key, []))
}

violation contains make_diag_full("pf-networkfirewall-tls-scopes-required", "ERROR", name,
	sprintf("Properties.TLSInspectionConfiguration.ServerCertificateConfigurations[%d].Scopes", [i]),
	"this ServerCertificateConfiguration has no Scopes, so nothing says which traffic to decrypt; CreateTLSInspectionConfiguration answers \"Scopes cannot be null or empty\"",
	"Add a Scopes entry with Sources or Destinations, plus the ports and protocols to decrypt",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-settings.html") if {
	some [name, i, cfg] in _pf_nfwlib_tls_config
	count(_pf_nfwtls_scopes(cfg)) == 0
}

violation contains make_diag_full("pf-networkfirewall-tls-scopes-required", "ERROR", name,
	sprintf("Properties.TLSInspectionConfiguration.ServerCertificateConfigurations[%d].Scopes[%d]", [ci, si]),
	"this scope names neither Sources nor Destinations; CreateTLSInspectionConfiguration answers \"Sources, Destinations cannot be null or empty\"",
	"Give the scope a Sources or a Destinations list",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-settings.html") if {
	some [name, ci, si, sc] in _pf_nfwlib_tls_scope
	count(_pf_nfwtls_addresses(sc)) == 0
}
