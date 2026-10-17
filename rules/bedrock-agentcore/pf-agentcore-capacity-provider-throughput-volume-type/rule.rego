package cdk_preflight

import rego.v1

# Throughput is "Only valid for gp3 volumes" (schema description) but the
# schema does not tie it to VolumeType; CreateCapacityProvider fails with
# "throughput is not valid for volumeType io2". VolumeType defaults to gp3, so
# only an explicit other type is checked. Only Volumes[] is measured.
violation contains make_diag_full("pf-agentcore-capacity-provider-throughput-volume-type", "ERROR", name,
	sprintf("Properties.ComputeConfiguration.Ec2Configuration.Volumes.%d.EbsConfiguration.Throughput", [v.i]),
	sprintf("Throughput applies only to gp3; CreateCapacityProvider fails with \"throughput is not valid for volumeType %s\"", [t]),
	"Drop Throughput, or use VolumeType gp3",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_EbsVolumeConfiguration.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::CapacityProvider")
	some v in _pf_accp_vols(name)
	t := object.get(v.ebs, "VolumeType", null)
	is_string(t)
	t != "gp3"
	object.get(v.ebs, "Throughput", "__pf_absent") != "__pf_absent"
}
