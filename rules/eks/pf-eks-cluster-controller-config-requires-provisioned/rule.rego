package cdk_preflight

import rego.v1

# The two kube-controller-manager knobs EKS only accepts on a Provisioned Control
# Plane scaling tier. Fires when the tier is absent (standard by default) or a
# literal "standard"; a Ref / Fn::If tier stays silent.
_pf_ekccp_knob := {
	"HorizontalPodAutoscalerControllerConfig": "HorizontalPodAutoscalerSyncPeriod",
	"PodGcControllerConfig": "TerminatedPodGcThreshold",
}

_pf_ekccp_standard(name) if {
	not _pf_ekslib_has(name, "ControlPlaneScalingConfig")
}

_pf_ekccp_standard(name) if {
	sc := _pf_ekslib_get(name, "ControlPlaneScalingConfig")
	is_object(sc)
	not _pf_ekslib_ohas(sc, "Tier")
}

_pf_ekccp_standard(name) if {
	sc := _pf_ekslib_get(name, "ControlPlaneScalingConfig")
	_pf_ekslib_oget(sc, "Tier") == "standard"
}

violation contains make_diag_full("pf-eks-cluster-controller-config-requires-provisioned", "ERROR", name,
	sprintf("Properties.KubeControllerManagerConfig.%s.%s", [grp, knob]),
	sprintf("%s is only accepted on a Provisioned Control Plane tier; CreateCluster fails with \"Kubernetes Control Plane configuration 'kubeControllerManagerConfig...' is not supported for this Provisioned Control Plane scaling tier.\"", [knob]),
	"Set ControlPlaneScalingConfig.Tier to a provisioned tier (tier-xl or larger), or remove the setting",
	"https://docs.aws.amazon.com/eks/latest/userguide/control-plane-parameters.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	cm := _pf_ekslib_get(name, "KubeControllerManagerConfig")
	some grp, knob in _pf_ekccp_knob
	g := _pf_ekslib_oget(cm, grp)
	_pf_ekslib_ohas(g, knob)
	_pf_ekccp_standard(name)
}
