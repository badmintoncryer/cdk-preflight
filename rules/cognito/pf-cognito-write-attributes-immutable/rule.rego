package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-write-attributes-immutable", "ERROR", name,
	sprintf("Properties.WriteAttributes.%d", [a.index]),
	sprintf("WriteAttributes has '%s', which no app client may write; the client create fails with \"Invalid write attributes specified while creating a client\"", [a.value]),
	"Drop email_verified / phone_number_verified / sub from WriteAttributes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	some a in flatten_list(name, "Properties.WriteAttributes")
	a.value in {"email_verified", "phone_number_verified", "sub"}
}
