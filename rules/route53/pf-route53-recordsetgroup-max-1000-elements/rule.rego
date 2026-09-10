package cdk_preflight

import rego.v1

_pf_r53_rsg1k_n(g) := sum([count(_pf_r53lib_vals(it.value)) |
	some it in flatten_list(g, "Properties.RecordSets")
])

violation contains make_diag_full("pf-route53-recordsetgroup-max-1000-elements", "ERROR", name,
	"Properties.RecordSets",
	sprintf("This record set group carries %d ResourceRecords values; one ChangeResourceRecordSets request accepts at most 1000", [n]),
	"Split the record sets across several AWS::Route53::RecordSetGroup resources",
	"https://docs.aws.amazon.com/general/latest/gr/r53.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	n := _pf_r53_rsg1k_n(name)
	n > 1000
}
