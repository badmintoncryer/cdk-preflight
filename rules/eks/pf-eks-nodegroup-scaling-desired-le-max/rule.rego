package cdk_preflight

import rego.v1

# The pass fixture sits on the limit (DesiredSize == MaxSize == 1), so
# deploying it would start one instance; the bench runs fail-only.

violation contains make_diag_full("pf-eks-nodegroup-scaling-desired-le-max", "ERROR", name,
	"Properties.ScalingConfig.DesiredSize",
	sprintf("DesiredSize %v is greater than MaxSize %v (\"desiredSize can't be greater than maxSize\")", [d, mx]),
	"Keep DesiredSize <= MaxSize",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-nodegroup-scalingconfig.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	d := to_number(resolve(name, "Properties.ScalingConfig.DesiredSize"))
	mx := to_number(resolve(name, "Properties.ScalingConfig.MaxSize"))
	d > mx
}
