package cdk_preflight

import rego.v1

_pf_r53_wmax_n(g, k) := count([1 |
	some it in flatten_list(g, "Properties.RecordSets")
	_pf_r53lib_key(it.value) == k
	"Weight" in _pf_r53lib_kinds(it.value)
])

violation contains make_diag_full("pf-route53-weighted-max-100-same-name-type", "ERROR", name,
	"Properties.RecordSets",
	sprintf("'%s' has %d weighted record sets; Route 53 allows at most 100 per name and type", [k, n]),
	"Keep at most 100 weighted record sets for one name and type",
	"https://docs.aws.amazon.com/general/latest/gr/r53.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some a in flatten_list(name, "Properties.RecordSets")
	"Weight" in _pf_r53lib_kinds(a.value)
	k := _pf_r53lib_key(a.value)
	n := _pf_r53_wmax_n(name, k)
	n > 100
}
