package cdk_preflight

import rego.v1

# WITH_TRAFFIC_CONTROL means CodeDeploy moves instances in and out of a load
# balancer, so on the EC2/On-Premises platform it needs one to move them in and
# out of. Lambda also uses WITH_TRAFFIC_CONTROL and carries no LoadBalancerInfo,
# so the rule only speaks when the application it names is a Server one.
_pf_cdtcrlb_lists := ["ElbInfoList", "TargetGroupInfoList", "TargetGroupPairInfoList"]

_pf_cdtcrlb_has_lb(name) if {
	some k in _pf_cdtcrlb_lists
	count(flatten_list(name, sprintf("Properties.LoadBalancerInfo.%s", [k]))) > 0
}

violation contains make_diag_full("pf-codedeploy-dg-traffic-control-requires-load-balancer", "ERROR", name,
	"Properties.LoadBalancerInfo",
	"DeploymentStyle.DeploymentOption is WITH_TRAFFIC_CONTROL but LoadBalancerInfo names no load balancer or target group; the deployment group create fails with \"The deploymentOption value is set to WITH_TRAFFIC_CONTROL, but no load balancer or target group has been specified in loadBalancerInfo.\"",
	"Name a load balancer in LoadBalancerInfo, or use WITHOUT_TRAFFIC_CONTROL",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-loadbalancerinfo.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	_pf_codedeploylib_dg_platform(name) == "Server"
	resolve(name, "Properties.DeploymentStyle.DeploymentOption") == "WITH_TRAFFIC_CONTROL"
	not _pf_cdtcrlb_has_lb(name)
}
