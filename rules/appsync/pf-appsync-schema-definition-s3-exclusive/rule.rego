package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-schema-definition-s3-exclusive", "ERROR", name,
	"Properties.DefinitionS3Location",
	"both Definition and DefinitionS3Location are set; the schema create rejects two sources for the same SDL",
	"Keep either Definition or DefinitionS3Location",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appsync-graphqlschema.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLSchema")
	is_string(resolve(name, "Properties.Definition"))
	is_string(resolve(name, "Properties.DefinitionS3Location"))
}
