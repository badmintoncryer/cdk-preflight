package cdk_preflight

import rego.v1

# Application Auto Scaling creates a service-linked role for the namespaces that
# support one; Amazon EMR does not, so RegisterScalableTarget refuses an
# elasticmapreduce target that carries no RoleARN. The check runs before the
# instance group is looked up, so the wrong template never reaches the cluster.
violation contains make_diag_full("pf-appautoscaling-rolearn-required-no-slr", "ERROR", name,
	"Properties.RoleARN",
	"ServiceNamespace elasticmapreduce has no service-linked role and no RoleARN is set; RegisterScalableTarget fails with \"Role ARN must be specified\"",
	"Set RoleARN to an IAM role that lets Application Auto Scaling modify the EMR instance group",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_RegisterScalableTarget.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	resolve(name, "Properties.ServiceNamespace") == "elasticmapreduce"
	not _pf_aaslib_has(name, "RoleARN")
}
