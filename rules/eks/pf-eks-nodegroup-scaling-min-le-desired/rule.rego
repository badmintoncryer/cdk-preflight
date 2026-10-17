package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-scaling-min-le-desired", "ERROR", name,
	"Properties.ScalingConfig.MinSize",
	sprintf("MinSize %v is greater than DesiredSize %v (\"minSize can't be greater than desiredSize\")", [mn, d]),
	"Keep MinSize <= DesiredSize",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-nodegroup-scalingconfig.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	mn := _pf_num(name, "Properties.ScalingConfig.MinSize")
	d := _pf_num(name, "Properties.ScalingConfig.DesiredSize")
	mn > d
}
