package cdk_preflight

import rego.v1

_pf_r53_rtypes := {"A", "AAAA", "CAA", "CNAME", "DS", "HTTPS", "MX", "NAPTR", "NS", "PTR", "SOA", "SPF", "SRV", "SSHFP", "SVCB", "TLSA", "TXT"}

violation contains make_diag_full("pf-route53-record-type-enum", "ERROR", name,
	"Properties.Type",
	sprintf("'%s' is not a record type Route 53 supports", [t]),
	"Use one of SOA, A, TXT, NS, CNAME, MX, NAPTR, PTR, SRV, SPF, AAAA, CAA, DS, TLSA, SSHFP, SVCB, HTTPS",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	t := _pf_r53lib_type(rs)
	not t in _pf_r53_rtypes
}

violation contains make_diag_full("pf-route53-record-type-enum", "ERROR", name,
	sprintf("Properties.RecordSets[%d].Type", [_pf_it.index]),
	sprintf("'%s' is not a record type Route 53 supports", [t]),
	"Use one of SOA, A, TXT, NS, CNAME, MX, NAPTR, PTR, SRV, SPF, AAAA, CAA, DS, TLSA, SSHFP, SVCB, HTTPS",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	t := _pf_r53lib_type(rs)
	not t in _pf_r53_rtypes
}
