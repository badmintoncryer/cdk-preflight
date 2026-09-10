package cdk_preflight

import rego.v1

_pf_r53_svcb_keys := {"alpn", "dohpath", "ech", "ipv4hint", "ipv6hint", "no-default-alpn", "ohttp", "port"}

_pf_r53_svcb_valued := {"alpn", "dohpath", "ech", "ipv4hint", "ipv6hint", "port"}

_pf_r53_svcb_keyset(f) := {k |
	some i in numbers.range(2, count(f) - 1)
	k := split(f[i], "=")[0]
}

violation contains make_diag_full("pf-route53-svcparams-key-value-format", "ERROR", name,
	"Properties.ResourceRecords",
	sprintf("The SvcParam '%s' needs a value: write it as %s=<value>", [p, k]),
	"Write the parameter as key=value (comma-separate multiple values)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	_pf_r53lib_type(rs) == "HTTPS"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) >= 3
	some i in numbers.range(2, count(f) - 1)
	p := f[i]
	k := split(p, "=")[0]
	k in _pf_r53_svcb_valued
	not contains(p, "=")
}

violation contains make_diag_full("pf-route53-svcparams-key-value-format", "ERROR", name,
	sprintf("Properties.RecordSets[%d].ResourceRecords", [_pf_it.index]),
	sprintf("The SvcParam '%s' needs a value: write it as %s=<value>", [p, k]),
	"Write the parameter as key=value (comma-separate multiple values)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	_pf_r53lib_type(rs) == "HTTPS"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) >= 3
	some i in numbers.range(2, count(f) - 1)
	p := f[i]
	k := split(p, "=")[0]
	k in _pf_r53_svcb_valued
	not contains(p, "=")
}

violation contains make_diag_full("pf-route53-svcparams-key-value-format", "ERROR", name,
	"Properties.ResourceRecords",
	sprintf("The SvcParam '%s' needs a value: write it as %s=<value>", [p, k]),
	"Write the parameter as key=value (comma-separate multiple values)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	_pf_r53lib_type(rs) == "SVCB"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) >= 3
	some i in numbers.range(2, count(f) - 1)
	p := f[i]
	k := split(p, "=")[0]
	k in _pf_r53_svcb_valued
	not contains(p, "=")
}

violation contains make_diag_full("pf-route53-svcparams-key-value-format", "ERROR", name,
	sprintf("Properties.RecordSets[%d].ResourceRecords", [_pf_it.index]),
	sprintf("The SvcParam '%s' needs a value: write it as %s=<value>", [p, k]),
	"Write the parameter as key=value (comma-separate multiple values)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	_pf_r53lib_type(rs) == "SVCB"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) >= 3
	some i in numbers.range(2, count(f) - 1)
	p := f[i]
	k := split(p, "=")[0]
	k in _pf_r53_svcb_valued
	not contains(p, "=")
}
