package cdk_preflight

import rego.v1

# ISO 3166-1 alpha-2（CLDR の特殊コードは除外し、迷ったら許可側に倒してある）
_pf_r53_countries := {
	"AC", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AN", "AO",
	"AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ", "BA", "BB",
	"BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN",
	"BO", "BQ", "BR", "BS", "BT", "BU", "BV", "BW", "BY", "BZ",
	"CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM",
	"CN", "CO", "CP", "CQ", "CR", "CS", "CU", "CV", "CW", "CX",
	"CY", "CZ", "DD", "DE", "DG", "DJ", "DK", "DM", "DO", "DY",
	"DZ", "EA", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI",
	"FJ", "FK", "FM", "FO", "FR", "FX", "GA", "GB", "GD", "GE",
	"GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR",
	"GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT",
	"HU", "HV", "IC", "ID", "IE", "IL", "IM", "IN", "IO", "IQ",
	"IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH",
	"KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB",
	"LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA",
	"MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN",
	"MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX",
	"MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NH", "NI", "NL",
	"NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
	"PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY",
	"QA", "RE", "RH", "RO", "RS", "RU", "RW", "SA", "SB", "SC",
	"SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN",
	"SO", "SR", "SS", "ST", "SU", "SV", "SX", "SY", "SZ", "TA",
	"TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN",
	"TO", "TP", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UK",
	"UM", "US", "UY", "UZ", "VA", "VC", "VD", "VE", "VG", "VI",
	"VN", "VU", "WF", "WS", "XK", "YD", "YE", "YT", "YU", "ZA",
	"ZM", "ZR", "ZW",
}

violation contains make_diag_full("pf-route53-geolocation-country-code-iso", "ERROR", name,
	"Properties.GeoLocation.CountryCode",
	sprintf("'%s' is not an ISO 3166-1 alpha-2 country code; Route 53 rejects the record with \"Cannot find location\"", [c]),
	"Use a real two-letter country code, or '*' for the default location",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geo.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	g := _pf_r53lib_get(rs, "GeoLocation")
	is_object(g)
	c := object.get(g, "CountryCode", null)
	is_string(c)
	c != "*"
	not c in _pf_r53_countries
}

violation contains make_diag_full("pf-route53-geolocation-country-code-iso", "ERROR", name,
	sprintf("Properties.RecordSets[%d].GeoLocation.CountryCode", [_pf_it.index]),
	sprintf("'%s' is not an ISO 3166-1 alpha-2 country code; Route 53 rejects the record with \"Cannot find location\"", [c]),
	"Use a real two-letter country code, or '*' for the default location",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geo.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	g := _pf_r53lib_get(rs, "GeoLocation")
	is_object(g)
	c := object.get(g, "CountryCode", null)
	is_string(c)
	c != "*"
	not c in _pf_r53_countries
}
