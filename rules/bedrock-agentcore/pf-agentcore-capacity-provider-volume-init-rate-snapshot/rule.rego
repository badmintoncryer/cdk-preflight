package cdk_preflight

import rego.v1

# The schema description says VolumeInitializationRate applies to volumes
# created from a snapshot, but nothing ties it to SnapshotId;
# CreateCapacityProvider fails with "volumeInitializationRate may only be set
# when snapshotId is provided".
violation contains make_diag_full("pf-agentcore-capacity-provider-volume-init-rate-snapshot", "ERROR", name,
	sprintf("Properties.ComputeConfiguration.Ec2Configuration.LaunchTemplateSource.LaunchParameters.EphemeralVolumes.%d.Ebs.VolumeInitializationRate", [e.i]),
	"VolumeInitializationRate is set without SnapshotId; CreateCapacityProvider fails with \"volumeInitializationRate may only be set when snapshotId is provided\"",
	"Drop VolumeInitializationRate, or create the volume from a snapshot (SnapshotId)",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_LaunchParameters.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::CapacityProvider")
	some e in _pf_accp_ephemeral(name)
	ebs := object.get(e.v, "Ebs", null)
	is_object(ebs)
	object.get(ebs, "VolumeInitializationRate", "__pf_absent") != "__pf_absent"
	object.get(ebs, "SnapshotId", "__pf_absent") == "__pf_absent"
}
