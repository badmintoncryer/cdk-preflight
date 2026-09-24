package cdk_preflight

import rego.v1

_pf_iotppa_ok(p) if {
	parts := split(p, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "iot"
	startswith(parts[5], "cert/")
}

_pf_iotppa_ok(p) if regex.match(`^[a-z][a-z0-9-]+-[0-9]:[0-9a-fA-F-]{36}$`, p)

violation contains make_diag_full("pf-iot-policyprincipal-principal-format", "ERROR", name,
	"Properties.Principal",
	sprintf("Principal '%s' is neither a certificate ARN (arn:<partition>:iot:<region>:<account>:cert/<id>) nor a Cognito identity (<region>:<uuid>); AttachPrincipalPolicy answers \"InvalidRequestException: Invalid principal type\"", [p]),
	"Pass the certificate ARN (Fn::GetAtt of the AWS::IoT::Certificate) or a Cognito identity id",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_AttachPrincipalPolicy.html") if {
	some name in resources_of_type("AWS::IoT::PolicyPrincipalAttachment")
	p := _pf_iotlib_lit(name, "Properties.Principal")
	not _pf_iotppa_ok(p)
}
