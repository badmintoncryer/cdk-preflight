package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-set-identifier-length", "ERROR", name,
	"Properties.SetIdentifier",
	sprintf("SetIdentifier is %d characters; the Route 53 API requires 1-128 even though the CloudFormation reference says Minimum: 0", [count(sid)]),
	"Give the record set a SetIdentifier of 1-128 characters, unique within its Name and Type",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	sid := _pf_r53lib_str(rs, "SetIdentifier")
	count(sid) > 128
}

violation contains make_diag_full("pf-route53-set-identifier-length", "ERROR", name,
	sprintf("Properties.RecordSets[%d].SetIdentifier", [_pf_it.index]),
	sprintf("SetIdentifier is %d characters; the Route 53 API requires 1-128 even though the CloudFormation reference says Minimum: 0", [count(sid)]),
	"Give the record set a SetIdentifier of 1-128 characters, unique within its Name and Type",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	sid := _pf_r53lib_str(rs, "SetIdentifier")
	count(sid) > 128
}

violation contains make_diag_full("pf-route53-set-identifier-length", "ERROR", name,
	"Properties.SetIdentifier",
	"SetIdentifier is empty; the Route 53 API requires 1-128 characters even though the CloudFormation reference says Minimum: 0",
	"Give the record set a SetIdentifier of 1-128 characters, unique within its Name and Type",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	sid := _pf_r53lib_str(rs, "SetIdentifier")
	sid == ""
}

violation contains make_diag_full("pf-route53-set-identifier-length", "ERROR", name,
	sprintf("Properties.RecordSets[%d].SetIdentifier", [_pf_it.index]),
	"SetIdentifier is empty; the Route 53 API requires 1-128 characters even though the CloudFormation reference says Minimum: 0",
	"Give the record set a SetIdentifier of 1-128 characters, unique within its Name and Type",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	sid := _pf_r53lib_str(rs, "SetIdentifier")
	sid == ""
}
