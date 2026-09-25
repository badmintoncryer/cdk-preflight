package cdk_preflight

import rego.v1

# ISO 3166-1 alpha-2, officially assigned only, plus XK (Kosovo, which MaxMind
# assigns and the service accepts). All 250 were taken in one CreateRuleGroup
# DryRun; the reserved and withdrawn codes AC, AN, AP, CS, EA, EU, IC, SU, TA,
# TP, UK and YU were each refused, so this is the service's own set.
_pf_nfwgeo_countries := {
	"AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR",
	"AS", "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE",
	"BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ",
	"BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD",
	"CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR",
	"CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM",
	"DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI",
	"FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
	"GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS",
	"GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU",
	"ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT",
	"JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN",
	"KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK",
	"LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME",
	"MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ",
	"MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
	"NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU",
	"NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM",
	"PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS",
	"RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI",
	"SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV",
	"SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK",
	"TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA",
	"UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
	"VN", "VU", "WF", "WS", "XK", "YE", "YT", "ZA", "ZM", "ZW",
}

# The comma-separated arguments of every geoip option on one line, upper-cased
# and with the "!" negation stripped. "geoip:US", "geoip:src,US",
# "geoip:any,US,CA", "geoip:src,!CN" and lower-case "geoip:src,us" are all
# accepted, so the direction word is skipped rather than required.
_pf_nfwgeo_tokens(l) := [t |
	some raw in split(concat(",", _pf_nfwlib_option_values(l, "geoip")), ",")
	t := upper(trim(trim_prefix(trim(raw, " \t"), "!"), " \t"))
	t != ""
]

_pf_nfwgeo_bad(l) := {t |
	some t in _pf_nfwgeo_tokens(l)
	not t in {"SRC", "DST", "BOTH", "ANY"}
	not t in _pf_nfwgeo_countries
}

violation contains make_diag_full("pf-networkfirewall-suricata-geoip-country-code", "ERROR", name,
	"Properties.RuleGroup.RulesSource.RulesString",
	sprintf("geoip in the rule '%s' names %s, which is not a country code Network Firewall knows; CreateRuleGroup answers \"reason: Rule contains an incorrect country code\"", [_pf_nfwlib_snip(l), c]),
	"Use an ISO 3166-1 alpha-2 code (GB, not UK) - continent codes such as EU and AP are refused",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-groups-geo-ip-filtering.html") if {
	some [name, _, l] in _pf_nfwlib_line
	bad := _pf_nfwgeo_bad(l)
	count(bad) > 0
	c := concat(", ", sort(bad))
}
