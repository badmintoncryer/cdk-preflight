package cdk_preflight

import rego.v1

_pf_schemadefinitionors3required_absent(n, k) if {
	props := input.resources[n].properties
	is_object(props)
	object.get(props, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-appsync-schema-definition-or-s3-required", "ERROR", name,
	"Properties.Definition",
	"neither Definition nor DefinitionS3Location is set; the schema create has nothing to upload",
	"Set Properties.Definition to the SDL, or DefinitionS3Location to an S3 object holding it",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appsync-graphqlschema.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLSchema")
	_pf_schemadefinitionors3required_absent(name, "Definition")
	_pf_schemadefinitionors3required_absent(name, "DefinitionS3Location")
}
