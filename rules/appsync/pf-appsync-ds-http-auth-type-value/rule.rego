package cdk_preflight

import rego.v1

# The engine knows this allowed-value list but reports it as W3030 (WARN),
# which never blocks a deploy; see AGENTS.md on the gray zone.
violation contains make_diag_full("pf-appsync-ds-http-auth-type-value", "ERROR", name,
	"Properties.HttpConfig.AuthorizationConfig.AuthorizationType",
	sprintf("AuthorizationType '%s' is not AWS_IAM; the data source create rejects the value", [v]),
	"Use AWS_IAM",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-datasource.html") if {
	some name in resources_of_type("AWS::AppSync::DataSource")
	v := resolve(name, "Properties.HttpConfig.AuthorizationConfig.AuthorizationType")
	is_string(v)
	not v in {"AWS_IAM"}
}
