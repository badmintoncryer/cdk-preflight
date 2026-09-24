package cdk_preflight

import rego.v1

# lambda:function:ProvisionedConcurrency takes function:<name>:<version|alias>.
# $LATEST is the one qualifier the service refuses, because provisioned
# concurrency is only allocatable on a published version or an alias.
violation contains make_diag_full("pf-appautoscaling-lambda-resource-id-qualifier", "ERROR", name,
	"Properties.ResourceId",
	sprintf("ResourceId '%s' qualifies the function with $LATEST; RegisterScalableTarget fails with \"$LATEST is not a supported qualifier for Auto Scaling\"", [rid]),
	"Publish a version and point the ResourceId at it or at an alias (function:my-function:1 or function:my-function:live)",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_RegisterScalableTarget.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	resolve(name, "Properties.ScalableDimension") == "lambda:function:ProvisionedConcurrency"
	rid := resolve(name, "Properties.ResourceId")
	is_string(rid)
	endswith(rid, ":$LATEST")
}
