package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-ds-dynamodb-region-mismatch", "ERROR", name,
	"Properties.DynamoDBConfig.AwsRegion",
	sprintf("DynamoDBConfig.AwsRegion '%s' is not a region name; the data source create fails because there is no such region to reach the table in", [r]),
	"Use a region name such as us-east-1",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-datasource.html") if {
	some name in resources_of_type("AWS::AppSync::DataSource")
	r := resolve(name, "Properties.DynamoDBConfig.AwsRegion")
	is_string(r)
	not regex.match(`^[a-z]{2}(-[a-z]+)+-[0-9]$`, r)
}
