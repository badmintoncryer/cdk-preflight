package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-failover-enum", "ERROR", name,
	"Properties.Failover",
	sprintf("Failover must be PRIMARY or SECONDARY, got '%s'", [fo]),
	"Use PRIMARY or SECONDARY",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	fo := _pf_r53lib_str(rs, "Failover")
	not fo in {"PRIMARY", "SECONDARY"}
}

violation contains make_diag_full("pf-route53-failover-enum", "ERROR", name,
	sprintf("Properties.RecordSets[%d].Failover", [_pf_it.index]),
	sprintf("Failover must be PRIMARY or SECONDARY, got '%s'", [fo]),
	"Use PRIMARY or SECONDARY",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	fo := _pf_r53lib_str(rs, "Failover")
	not fo in {"PRIMARY", "SECONDARY"}
}
