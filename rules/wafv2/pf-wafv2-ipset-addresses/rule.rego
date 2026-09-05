package cdk_preflight

import rego.v1

_pf_wafip_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_CreateIPSet.html"

_pf_wafip_fix := "Write every address as network/prefix (192.0.2.44/32, 192.0.2.0/24, 2001:db8::/32) matching IPAddressVersion, with prefix 1-32 (IPv4) or 1-128 (IPv6) and the host bits zeroed"

_pf_wafip contains [name, k, a, ver] if {
	some name in resources_of_type("AWS::WAFv2::IPSet")
	addrs := input.resources[name].properties.Addresses
	some k
	a := addrs[k]
	is_string(a)
	ver := resolve(name, "Properties.IPAddressVersion")
}

_pf_wafip_path(k) := sprintf("Properties.Addresses[%d]", [k])

_pf_wafip_msg := "the create call fails with \"The parameter contains formatting that is not valid.\""

_pf_wafip_v4 := "^[0-9]{1,3}(\\.[0-9]{1,3}){3}$"

# [ip, prefix] of a syntactically plausible CIDR; undefined otherwise
_pf_wafip_split(a) := [ip, p] if {
	regex.match("^[^/]+/[0-9]{1,3}$", a)
	parts := split(a, "/")
	ip := parts[0]
	p := to_number(parts[1])
}

violation contains make_diag_full("pf-wafv2-ipset-addresses", "ERROR", name, _pf_wafip_path(k),
	sprintf("'%s' is not in CIDR notation (network/prefix); %s", [a, _pf_wafip_msg]),
	_pf_wafip_fix, _pf_wafip_url) if {
	some [name, k, a, ver] in _pf_wafip
	not _pf_wafip_split(a)
}

_pf_wafip_kind(ip) := "IPV4" if regex.match(_pf_wafip_v4, ip)

_pf_wafip_kind(ip) := "IPV6" if {
	not regex.match(_pf_wafip_v4, ip)
	regex.match("^[0-9A-Fa-f:]+$", ip)
	contains(ip, ":")
	count(regex.find_n("::", ip, -1)) <= 1
}

violation contains make_diag_full("pf-wafv2-ipset-addresses", "ERROR", name, _pf_wafip_path(k),
	sprintf("'%s' is neither an IPv4 nor an IPv6 address (IPv4-mapped IPv6, zone ids and spaces are not accepted); %s", [ip, _pf_wafip_msg]),
	_pf_wafip_fix, _pf_wafip_url) if {
	some [name, k, a, ver] in _pf_wafip
	[ip, p] := _pf_wafip_split(a)
	not _pf_wafip_kind(ip)
}

violation contains make_diag_full("pf-wafv2-ipset-addresses", "ERROR", name, _pf_wafip_path(k),
	sprintf("'%s' is an %s address but IPAddressVersion is %s; %s", [a, kind, ver, _pf_wafip_msg]),
	_pf_wafip_fix, _pf_wafip_url) if {
	some [name, k, a, ver] in _pf_wafip
	[ip, p] := _pf_wafip_split(a)
	kind := _pf_wafip_kind(ip)
	kind != ver
}

_pf_wafip_octets(ip) := [to_number(o) | some j; o := split(ip, ".")[j]]

violation contains make_diag_full("pf-wafv2-ipset-addresses", "ERROR", name, _pf_wafip_path(k),
	sprintf("'%s' has an octet above 255; %s", [a, _pf_wafip_msg]),
	_pf_wafip_fix, _pf_wafip_url) if {
	some [name, k, a, ver] in _pf_wafip
	[ip, p] := _pf_wafip_split(a)
	_pf_wafip_kind(ip) == "IPV4"
	some o in _pf_wafip_octets(ip)
	o > 255
}

_pf_wafip_max := {"IPV4": 32, "IPV6": 128}

violation contains make_diag_full("pf-wafv2-ipset-addresses", "ERROR", name, _pf_wafip_path(k),
	sprintf("prefix length /%d is outside 1..%d for %s (/0 is never accepted); %s", [p, _pf_wafip_max[kind], kind, _pf_wafip_msg]),
	_pf_wafip_fix, _pf_wafip_url) if {
	some [name, k, a, ver] in _pf_wafip
	[ip, p] := _pf_wafip_split(a)
	kind := _pf_wafip_kind(ip)
	_pf_wafip_bad_prefix(p, _pf_wafip_max[kind])
}

_pf_wafip_bad_prefix(p, max) if p < 1

_pf_wafip_bad_prefix(p, max) if p > max

_pf_wafip_num(o) := ((o[0] * 16777216) + (o[1] * 65536)) + ((o[2] * 256) + o[3])

# ponytail: host bits are checked for IPv4 only; an IPv6 address with host bits set slips through
violation contains make_diag_full("pf-wafv2-ipset-addresses", "ERROR", name, _pf_wafip_path(k),
	sprintf("'%s' has host bits set for a /%d prefix (write the network address, e.g. %s); %s", [a, p, _pf_wafip_net(o, p), _pf_wafip_msg]),
	_pf_wafip_fix, _pf_wafip_url) if {
	some [name, k, a, ver] in _pf_wafip
	[ip, p] := _pf_wafip_split(a)
	_pf_wafip_kind(ip) == "IPV4"
	p >= 1
	p <= 32
	o := _pf_wafip_octets(ip)
	count([x | some x in o; x > 255]) == 0
	bits.and(_pf_wafip_num(o), bits.lsh(1, 32 - p) - 1) != 0
}

_pf_wafip_net(o, p) := out if {
	n := _pf_wafip_num(o) - bits.and(_pf_wafip_num(o), bits.lsh(1, 32 - p) - 1)
	out := sprintf("%d.%d.%d.%d/%d", [floor(n / 16777216), bits.and(floor(n / 65536), 255), bits.and(floor(n / 256), 255), bits.and(n, 255), p])
}
