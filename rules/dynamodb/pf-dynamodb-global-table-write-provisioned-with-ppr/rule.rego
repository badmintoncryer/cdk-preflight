package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-dynamodb-global-table-write-provisioned-with-ppr", "ERROR", name,
	"Properties.WriteProvisionedThroughputSettings",
	"WriteProvisionedThroughputSettings is set while BillingMode is PAY_PER_REQUEST; an on-demand global table has no provisioned write capacity",
	"Remove WriteProvisionedThroughputSettings, or switch BillingMode to PROVISIONED",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-globaltable.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	resolve(name, "Properties.BillingMode") == "PAY_PER_REQUEST"
	is_object(resolve(name, "Properties.WriteProvisionedThroughputSettings"))
}
