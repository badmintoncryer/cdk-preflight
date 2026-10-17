package cdk_preflight

import rego.v1

# CreateTargetGroup rejects Config.LambdaEventStructureVersion on any type
# other than LAMBDA ("IP Target Group does not support lambda event structure
# version"). The schema does not tie the field to the type.
violation contains make_diag_full("pf-vpclattice-tg-lambda-event-version-non-lambda", "ERROR", name,
	"Properties.Config.LambdaEventStructureVersion",
	sprintf("A %s target group takes no LambdaEventStructureVersion; CreateTargetGroup fails with \"%s Target Group does not support lambda event structure version\"", [t, t]),
	"Drop LambdaEventStructureVersion, or use Type LAMBDA",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_TargetGroupConfig.html") if {
	some name in _pf_vpcl_tgs
	t := _pf_vpcl_tgtype(name)
	t != "LAMBDA"
	_pf_vpcl_has(name, "Properties.Config.LambdaEventStructureVersion")
}
