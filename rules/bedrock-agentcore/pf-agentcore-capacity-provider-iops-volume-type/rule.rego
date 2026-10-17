package cdk_preflight

import rego.v1

# The schema allows Iops next to every VolumeType. CreateCapacityProvider
# rejects it for the volume types without provisioned IOPS ("iops is not valid
# for volumeType gp2"). VolumeType defaults to gp3, so only an explicit type is
# checked. Only Volumes[] is measured; RootVolume and EphemeralVolumes are not
# checked.
_pf_accpi_no_iops := {"standard", "gp2", "sc1", "st1"}

violation contains make_diag_full("pf-agentcore-capacity-provider-iops-volume-type", "ERROR", name,
	sprintf("Properties.ComputeConfiguration.Ec2Configuration.Volumes.%d.EbsConfiguration.Iops", [v.i]),
	sprintf("Volume type %s has no provisioned IOPS; CreateCapacityProvider fails with \"iops is not valid for volumeType %s\"", [t, t]),
	"Drop Iops, or use VolumeType gp3, io1 or io2",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_EbsVolumeConfiguration.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::CapacityProvider")
	some v in _pf_accp_vols(name)
	t := object.get(v.ebs, "VolumeType", null)
	t in _pf_accpi_no_iops
	object.get(v.ebs, "Iops", "__pf_absent") != "__pf_absent"
}
