package cdk_preflight

import rego.v1

# ServiceToken accepts any string; only SNS topic ARNs and Lambda function ARNs
# actually work. Unresolvable tokens (a GetAtt on a function in the same stack)
# are skipped rather than guessed at.
_pf_cfnsvctsvc_bad contains [name, arn, svc] if {
	some name in _pf_cfn_custom_resources
	arn := resolve(name, "Properties.ServiceToken")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	svc := parts[2]
	not svc in {"sns", "lambda"}
}

violation contains make_diag_full("pf-cfn-custom-servicetoken-service", "ERROR", name,
	"Properties.ServiceToken",
	sprintf("ServiceToken %s points at %s; CloudFormation fails the resource with \"Invalid service token\" because only SNS topic and Lambda function ARNs are accepted", [arn, svc]),
	"Point ServiceToken at an SNS topic ARN or a Lambda function ARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudformation-customresource.html") if {
	some [name, arn, svc] in _pf_cfnsvctsvc_bad
}
