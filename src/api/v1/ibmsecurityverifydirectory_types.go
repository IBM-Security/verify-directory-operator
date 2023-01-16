/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
)

// IBMSecurityVerifyDirectoryReplica defines details associated with a 
// single directory server replica.
type IBMSecurityVerifyDirectoryReplica struct {
	// A list of persistent volume claims which will be used by the 
	// replica.  Each replica must have its own PVC, and the PVC must be 
	// pre-created.
	PVCs []string `json:"pvcs"`
}

// IBMSecurityVerifyDirectoryImage defines the details associated with the
// docker images used by the operator.
type IBMSecurityVerifyDirectoryImage struct {
	//+kubebuilder:default=icr.io/isvd
	// The repository which is used to store the Verify Directory images. 
	// +optional
	Repo string `json:"repo,omitempty"`

	//+kubebuilder:default=latest
	// The label of the Verify Directory images to be used. 
	// +optional
	Label string `json:"label,omitempty"`

    // Image pull policy.
    // One of Always, Never, IfNotPresent.
    // Defaults to Always if :latest tag is specified, or IfNotPresent 
    // otherwise.
    // Cannot be updated.
    // More info: https://kubernetes.io/docs/concepts/containers/images#updating-images
    // +optional
    ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty" protobuf:"bytes,14,opt,name=imagePullPolicy,casttype=PullPolicy"`

	// ImagePullSecrets is an optional list of references to secrets in the same
	// namespace to use for pulling any of the images used by this PodSpec.
	// If specified, these secrets will be passed to individual puller 
	// implementations for them to use. For example,
	// in the case of docker, only DockerConfig type secrets are honored.
    // More info: 
    // https://kubernetes.io/docs/concepts/containers/images#specifying-imagepullsecrets-on-a-pod
    // +optional
    // +patchMergeKey=name
    // +patchStrategy=merge
    ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty" patchStrategy:"merge" patchMergeKey:"name" protobuf:"bytes,15,rep,name=imagePullSecrets"`
}

// IBMSecurityVerifyDirectoryProxy defines the details associated with the
// proxy which will be created by the operator.
type IBMSecurityVerifyDirectoryProxy struct {
	// The name of the PVC which will be used by the proxy.
	// +optional
	PVC string `json:"pvc"`
}

// for a ConfigMap configuration.
type IBMSecurityVerifyDirectoryConfigMapEntry struct {
	// The name of the ConfigMap which contains the configuration data.
	Name string `json:"name"`

	// The key within the ConfigMap which contains the configuration data.
	Key string `json:"key"`
}

// IBMSecurityVerifyDirectoryConfigMap defines the ConfigMaps which are used
// by the server and proxy.
type IBMSecurityVerifyDirectoryConfigMap struct {
	// The ConfigMap which contains the initial configuration data for the 
	// proxy.  This should include everything but the definition of the 
	// server-groups and suffixes as these will be automatically added to the
	// proxy configuration by the operator.
	Proxy IBMSecurityVerifyDirectoryConfigMapEntry `json:"proxy"`

	// The ConfigMap which contains the configuration data for the server 
	// which is being managed/replicated.
	Server IBMSecurityVerifyDirectoryConfigMapEntry `json:"server"`
}

// IBMSecurityVerifyDirectoryPods defines details when creating the server
// pods.
type IBMSecurityVerifyDirectoryPods struct {
	// Details associated with the docker images used by the operator.
	// +optional
	Image IBMSecurityVerifyDirectoryImage `json:"image,omitempty"`

	// +optional
	Proxy IBMSecurityVerifyDirectoryProxy `json:"proxy,omitempty"`

	// The configuration details for the proxy and server.
	ConfigMap IBMSecurityVerifyDirectoryConfigMap `json:"configMap"`

    // Compute Resources required by this container.
    // Cannot be updated.
    // More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    // +optional
    Resources corev1.ResourceRequirements `json:"resources,omitempty" protobuf:"bytes,8,opt,name=resources"`

    // List of sources to populate environment variables in the container.
    // The keys defined within a source must be a C_IDENTIFIER. All invalid keys
    // will be reported as an event when the container is starting. When a key 
    // exists in multiple sources, the value associated with the last source 
    // will take precedence.  Values defined by an Env with a duplicate key 
    // will take precedence.
    // Cannot be updated.
    // +optional
    EnvFrom []corev1.EnvFromSource `json:"envFrom,omitempty" protobuf:"bytes,19,rep,name=envFrom"`

    // List of environment variables to set in the container.
    // Cannot be updated.
    // +optional
    // +patchMergeKey=name
    // +patchStrategy=merge
    Env []corev1.EnvVar `json:"env,omitempty" patchStrategy:"merge" patchMergeKey:"name" protobuf:"bytes,7,rep,name=env"`

    // ServiceAccountName is the name of the ServiceAccount to use to run this
	// pod.
    // More info: 
    // https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
    // +optional
    ServiceAccountName string `json:"serviceAccountName,omitempty" protobuf:"bytes,8,opt,name=serviceAccountName"`
}

// IBMSecurityVerifyDirectorySpec defines the desired state of 
// IBMSecurityVerifyDirectory
type IBMSecurityVerifyDirectorySpec struct {
	// Details of the server replicas within the environment.
	Replicas IBMSecurityVerifyDirectoryReplica `json:"replicas"`

	// Details which are used when creating the server pods.
	Pods IBMSecurityVerifyDirectoryPods `json:"pods"`
}

// IBMSecurityVerifyDirectoryStatus defines the observed state of 
// IBMSecurityVerifyDirectory
type IBMSecurityVerifyDirectoryStatus struct {
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// IBMSecurityVerifyDirectory is the Schema for the 
// ibmsecurityverifydirectories API
type IBMSecurityVerifyDirectory struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IBMSecurityVerifyDirectorySpec   `json:"spec,omitempty"`
	Status IBMSecurityVerifyDirectoryStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IBMSecurityVerifyDirectoryList contains a list of IBMSecurityVerifyDirectory
type IBMSecurityVerifyDirectoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IBMSecurityVerifyDirectory `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IBMSecurityVerifyDirectory{}, &IBMSecurityVerifyDirectoryList{})
}
