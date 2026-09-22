package cdk_preflight

import rego.v1

# Judged only when DeferMaintenance is literally true: that is the branch where the
# CloudFormation handler is known to call ModifyClusterMaintenance after CreateCluster.
violation contains make_diag_full("pf-redshift-defer-maintenance-duration-endtime", "ERROR", name,
	"Properties.DeferMaintenanceDuration",
	"DeferMaintenanceDuration is set together with DeferMaintenanceEndTime; ModifyClusterMaintenance rejects the pair after the cluster is created (\"If you specify a duration, you can't specify an end time.\")",
	"Keep either DeferMaintenanceDuration or DeferMaintenanceEndTime, not both",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_ModifyClusterMaintenance.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	_pf_redshiftlib_true(name, "DeferMaintenance")
	_pf_redshiftlib_has(name, "DeferMaintenanceDuration")
	_pf_redshiftlib_has(name, "DeferMaintenanceEndTime")
}
