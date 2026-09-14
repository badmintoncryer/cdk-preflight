package cdk_preflight

import rego.v1

# Type picks the sub-block: the one it names has to be there and the other one
# has to be absent. AllAtOnce names neither, so it takes neither.
_pf_cdtrb_cfg(name) := trc if {
	trc := _pf_codedeploylib_obj(_pf_codedeploylib_props(name), "TrafficRoutingConfig")
}

violation contains make_diag_full("pf-codedeploy-config-traffic-routing-block-matches-type", "ERROR", name,
	sprintf("Properties.TrafficRoutingConfig.%v", [blk]),
	sprintf("TrafficRoutingConfig.Type is %v but %v is also set; the deployment configuration create fails with \"%vConfiguration should be null for %v type\"", [t, blk, blk, t]),
	sprintf("Drop %v, or set Type to %v", [blk, blk]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentconfig-trafficroutingconfig.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentConfig")
	trc := _pf_cdtrb_cfg(name)
	t := object.get(trc, "Type", null)
	_pf_codedeploylib_lit(t)
	some blk in ["TimeBasedCanary", "TimeBasedLinear"]
	blk != t
	_pf_codedeploylib_has(trc, blk)
}

violation contains make_diag_full("pf-codedeploy-config-traffic-routing-block-matches-type", "ERROR", name,
	sprintf("Properties.TrafficRoutingConfig.%v", [t]),
	sprintf("TrafficRoutingConfig.Type is %v but there is no %v block; the deployment configuration create fails with \"%vConfiguration should not be null for %v type\"", [t, t, t, t]),
	sprintf("Add the %v block with its interval and percentage, or use Type AllAtOnce", [t]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentconfig-trafficroutingconfig.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentConfig")
	trc := _pf_cdtrb_cfg(name)
	t := object.get(trc, "Type", null)
	t in {"TimeBasedCanary", "TimeBasedLinear"}
	not _pf_codedeploylib_has(trc, t)
}
