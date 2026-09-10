package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-set-identifier-unique-in-group", "ERROR", name,
	sprintf("Properties.RecordSets[%d]", [b.index]),
	sprintf("Two record sets for '%s' share the SetIdentifier '%s'; it is the key that tells them apart", [k, sid]),
	"Give each record set in the group its own SetIdentifier",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some a in flatten_list(name, "Properties.RecordSets")
	some b in flatten_list(name, "Properties.RecordSets")
	a.index < b.index
	k := _pf_r53lib_key(a.value)
	k == _pf_r53lib_key(b.value)
	sid := _pf_r53lib_str(a.value, "SetIdentifier")
	sid == _pf_r53lib_str(b.value, "SetIdentifier")
}
