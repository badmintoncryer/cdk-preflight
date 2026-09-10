package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-record-comment-length", "ERROR", name,
	"Properties.Comment",
	sprintf("Comment is %d characters; CloudFormation rejects anything over 256", [count(c)]),
	"Shorten the comment to 256 characters or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	c := _pf_r53lib_str(rs, "Comment")
	count(c) > 256
}

violation contains make_diag_full("pf-route53-record-comment-length", "ERROR", name,
	"Properties.Comment",
	sprintf("Comment is %d characters; CloudFormation rejects anything over 256", [count(c)]),
	"Shorten the comment to 256 characters or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	rs := _pf_r53lib_props(name)
	c := _pf_r53lib_str(rs, "Comment")
	count(c) > 256
}
