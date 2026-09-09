package cdk_preflight

import rego.v1

_pf_asgwpsi_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutWarmPool.html"

violation contains make_diag_full("pf-asg-wp-spot-incompatible", "ERROR", name,
	"Properties.AutoScalingGroupName",
	sprintf("launch template %s requests Spot instances (InstanceMarketOptions.MarketType), so the warm pool create fails with \"You can't add a warm pool to an Auto Scaling group that requests Spot Instances\"", [lt]),
	"Drop the warm pool, or launch the group on On-Demand capacity", _pf_asgwpsi_url) if {
	some name in resources_of_type("AWS::AutoScaling::WarmPool")
	lt := _pf_aslib_lt(_pf_aslib_group(name))
	resolve(lt, "Properties.LaunchTemplateData.InstanceMarketOptions.MarketType") == "spot"
}
