package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-custom-email-sender-kms", "ERROR", name,
	"Properties.LambdaConfig.KMSKeyID",
	"LambdaConfig.CustomEmailSender is set but KMSKeyID is not; the pool create fails with \"KMSKeyId parameter is required when Custom SMS/Email Lambda trigger is used.\"",
	"Set LambdaConfig.KMSKeyID to the key Cognito should encrypt the codes with",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	_pf_coglib_set(_pf_coglib_g2(name, "LambdaConfig", "CustomEmailSender"))
	_pf_coglib_absent(_pf_coglib_g2(name, "LambdaConfig", "KMSKeyID"))
}
