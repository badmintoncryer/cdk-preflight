package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-api-userpool-region-mismatch", "ERROR", name,
	"Properties.UserPoolConfig.UserPoolId",
	sprintf("UserPoolId is in region '%s' but UserPoolConfig.AwsRegion is '%s'; the API create fails because the pool cannot be found in the region it is looked up in", [prefix, r]),
	"Set UserPoolConfig.AwsRegion to the region the user pool id starts with",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appsync-graphqlapi-userpoolconfig.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	pool := resolve(name, "Properties.UserPoolConfig.UserPoolId")
	is_string(pool)
	r := resolve(name, "Properties.UserPoolConfig.AwsRegion")
	is_string(r)
	prefix := split(pool, "_")[0]
	regex.match(`^[a-z]{2}-[a-z]+-[0-9]$`, prefix)
	prefix != r
}
