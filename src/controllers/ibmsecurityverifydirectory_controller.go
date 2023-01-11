/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package controllers

/*****************************************************************************/

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"

	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/go-logr/logr"
	"github.com/go-yaml/yaml"

	ctrl  "sigs.k8s.io/controller-runtime"
	ibmv1 "github.com/ibm-security/verify-directory-operator/api/v1"
)

/*****************************************************************************/

/*
 * Some constants...
 */

const PVCLabel = "app.kubernetes.io/pvc-name"

/*****************************************************************************/

/*
 * IBMSecurityVerifyDirectoryReconciler reconciles an 
 * IBMSecurityVerifyDirectory object.
 */

type IBMSecurityVerifyDirectoryReconciler struct {
	client.Client
	Log logr.Logger
	Scheme *runtime.Scheme
}

/*****************************************************************************/

//+kubebuilder:rbac:groups=ibm.com,resources=ibmsecurityverifydirectories,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ibm.com,resources=ibmsecurityverifydirectories/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ibm.com,resources=ibmsecurityverifydirectories/finalizers,verbs=update

/*****************************************************************************/

/*
 * Reconcile is part of the main kubernetes reconciliation loop which aims to
 * move the current state of the cluster closer to the desired state.
 *
 * For more details, check Reconcile and its Result here:
 * - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.13.0/pkg/reconcile
 */

func (r *IBMSecurityVerifyDirectoryReconciler) Reconcile(
			ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	r.Log.V(9).Info("Entering a function", "Function", "Reconcile")

	/*
	 * Fetch the definition document.
	 */

	directory := &ibmv1.IBMSecurityVerifyDirectory{}
	err	   := r.Get(ctx, req.NamespacedName, directory)

	if err != nil {

		if kerrors.IsNotFound(err) {
			/*
			 * The requested object was not found.  This means that it has
			 * been deleted.
  			 */

			err = r.deleteDeployment(ctx, req)
		} else {
			/*
	  		 * There was an error reading the object - requeue the request.
			 */

			r.Log.Error(err, "Failed to get the VerifyDirectory resource")
		}

		return ctrl.Result{}, err
	}

	/*
	 * We now need to potentially create or update the deployment.
	 */

	/*
	 * Retrieve the list of existing pods for the deployment.
	 */

	existing, err := r.getExistingPods(ctx, req)

	if err != nil {
		r.setCondition(err, ctx, directory, 
							"Failed to retrieve the list of existing pods.")

		return ctrl.Result{}, err
	}

	r.Log.Info("Existing pods", 
					   	"Deployment.Namespace", req.Namespace,
			  			"Deployment.Name", req.Name,
						"Pods", existing)

	/*
	 * Work out the list of replicas to be deleted, and the list of
	 * replicas to be added.
	 */

	toBeDeleted, toBeAdded := r.analyseExistingPods(directory, existing)

	r.Log.Info("Updates required",
			"to be deleted", toBeDeleted,
			"to be added", toBeAdded)

	if len(toBeDeleted) == 0 && len(toBeAdded) == 0 {
		return ctrl.Result{}, nil
	}

	/*
	 * Get the port used by the server.
	 */

	port, secure, err := r.getServerPort(ctx, directory)

	if err != nil {
		r.setCondition(err, ctx, directory, 
			"Failed to obtain the server port information from the ConfigMap.")

		return ctrl.Result{}, err
	}

	/*
	 * Create the new replicas.
	 */

	err = r.createReplicas(
					ctx, req, directory, existing, toBeAdded, port, secure)

	if err != nil {
		r.setCondition(err, ctx, directory, 
					"Failed to create the new replicas.")

		return ctrl.Result{}, err
	}

	/*
	 * Now that we have created the replicas we need to deploy the
	 * front-end proxy.
	 */

	err = r.deployProxy(ctx, directory, port, secure)

	if err != nil {
		r.setCondition(err, ctx, directory, "Failed to deploy the proxy.")

		return ctrl.Result{}, err
	}

	/*
	 * Delete the replicas which have been removed from the deployment.
	 */

	err = r.deleteReplicas(ctx, req, directory, toBeDeleted)

	if err != nil {
		r.setCondition(err, ctx, directory, 
				"Failed to delete the obsolete replicas.")

		return ctrl.Result{}, err
	}

	/*
	 * Check the result so that we can set the condition of the
	 * deployment.
	 */

	r.Log.Info("Reconciled the document",
								"Deployment.Namespace", req.Namespace,
								"Deployment.Name", req.Name)

	r.setCondition(err, ctx, directory, "")

	return ctrl.Result{}, err
}

/*****************************************************************************/

/*
 * Delete a server from the environment.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) deleteDeployment(
			ctx context.Context, req ctrl.Request) (err error) {

	r.Log.Info("Deleting a Verify Directory resource",
				"Namespace", req.Namespace,
				"Name",      req.Name)

	err = nil

	/*
	 * Delete all of the services for the deployment.
	 */

	service := &corev1.Service{}
	opts    := []client.DeleteAllOfOption{
		client.InNamespace(req.Namespace),
		client.MatchingLabels(r.labelsForApp(req.Name, "")),
	}

	err = r.DeleteAllOf(ctx, service, opts...)

	if err != nil {
		return 
	}

	/*
	 * Delete all of the pods for the deployment.
	 */

	pod := &corev1.Pod{}

	err = r.DeleteAllOf(ctx, pod, opts...)

	if err != nil {
		return 
	}

	/*
	 * Delete all of the ConfigMaps for the deployment.
	 */

	configMap := &corev1.ConfigMap{}

	err = r.DeleteAllOf(ctx, configMap, opts...)

	if err != nil {
		return 
	}

	return
}

/*****************************************************************************/

/*
 * Create the required replicas for this deployment.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) createReplicas(
			ctx       context.Context, 
			req       ctrl.Request, 
			directory *ibmv1.IBMSecurityVerifyDirectory,
			existing  map[string]string,
			toBeAdded []string,
			port      int32,
			secure    bool) (err error) {

	err = nil

	/*
	 * Don't do anything here if there is nothing to be added.
	 */

	if len(toBeAdded) == 0 {
		return
	}

	/*
	 * Work out the principal.  If we have any existing replicas the first
	 * of the existing replicas will be principal, otherwise the first of
	 * the new replicas will be the principal.
	 */

	var principal string

	if len(existing) > 0 {

		for key, _ := range existing {
			principal = key
			break
		}

	} else {
		principal = toBeAdded[0]

		r.Log.Info("Creating the principal replica", "pvc", principal)

		/*
		 * The principal doesn't currently exist and so we need to create
		 * the principal now.
		 */

		var pod string

		pod, err = r.deployReplica(ctx, directory, port, principal)

		if err != nil {
			return
		}

		existing[principal] = pod

		/*
		 * If there are no additional replicas to be added we can simply
		 * return now.
		 */

		if len(toBeAdded) == 1 {
			return
		}
	}

	/*
	 * Iterate over each PVC which is to be added, creating the replication
	 * agreement with the principal.
	 */

	for _, pvcName := range toBeAdded {

		if pvcName != principal {
			r.Log.Info(
					"Creating the replication agreement for the new replica", 
					"pvc", pvcName)

			err = r.createReplicationAgreement(
								ctx, directory, port, principal, pvcName)

			if err != nil {
				return 
			}
		}
	}

	/*
	 * Stop the principal.
	 */

	// XXX: Multiple Replicas


	/*
	 * Iterate over each PVC which is to be added, initialising the replica
	 * and then deploying the replica.
	 */

	for _, pvcName := range toBeAdded {

		if pvcName != principal {
			/*
			 * Initialize the replica, which mostly involves seeding the
			 * replica with the data from the principal, and setting up the
			 * replication agreements between the new replica and the existing
			 * replicas.
			 */

			err = r.initializeReplica(
							ctx, directory, principal, pvcName, existing)

			if err != nil {
				return
			}

			/*
   			 * Deploy the replica.
   			 */

			var pod string

			pod, err = r.deployReplica(ctx, directory, port, pvcName)

			if err != nil {
				return
			}

			existing[pvcName] = pod
		}
	}

	/*
	 * Start the principal.
	 */

	// XXX: Multiple Replicas

	return 
}

/*****************************************************************************/

/*
 * Delete the replicas for this deployment which are no longer required.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) deleteReplicas(
			ctx         context.Context, 
			req         ctrl.Request, 
			directory   *ibmv1.IBMSecurityVerifyDirectory,
			toBeDeleted []string) (err error) {

	/*
	 * Process each of the replicas which are to be deleted.
	 */

	for idx, pvcName := range toBeDeleted {
		r.Log.Info("Deleting the replica", 
							strconv.FormatInt(int64(idx), 10), pvcName)

		/*
		 * Ensure that this replica is not the write-master according to the
		 * proxy.
		 */

		// XXX: Multiple Replicas

		/*
		 * Remove the replication agreement from each of the existing
		 * replicas.
		 */

		// XXX: Multiple Replicas

		/*
		 * Delete the service.
		 */

		service := &corev1.Service{}
		opts    := []client.DeleteAllOfOption{
			client.InNamespace(req.Namespace),
			client.MatchingLabels(r.labelsForApp(req.Name, pvcName)),
		}

		err = r.DeleteAllOf(ctx, service, opts...)

		if err != nil {
			return 
		}

		/*
		 * Delete the pod.
		 */

		pod := &corev1.Pod{}

		err = r.DeleteAllOf(ctx, pod, opts...)

		if err != nil {
			return 
		}
	}

	return nil
}

/*****************************************************************************/

/*
 * The following function is used to wrap the logic which updates the
 * condition for a failure.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) setCondition(
				err      error,
			  	ctx      context.Context,
			 	m        *ibmv1.IBMSecurityVerifyDirectory,
				msg      string) error {

	var condReason  string
	var condMessage string
	
	if m.Generation == 1 {
		condReason  = "DeploymentCreated"
		condMessage = "The deployment has been created."
	} else {
		condReason  = "DeploymentUpdated"
		condMessage = "The deployment has been updated."
	}
	
	currentTime := metav1.NewTime(time.Now())
	
	if err == nil {
		m.Status.Conditions = []metav1.Condition{{
			Type:               "Available",
			Status:             metav1.ConditionTrue,
			Reason:             condReason,
			Message:            condMessage,
			LastTransitionTime: currentTime,
		}}
	} else {
		m.Status.Conditions = []metav1.Condition{{
			Type:               "Available",
			Status:             metav1.ConditionFalse,
			Reason:             condReason,
			Message:            err.Error(),
			LastTransitionTime: currentTime,
		}}
	}
	
	if err := r.Status().Update(ctx, m); err != nil {
		r.Log.Error(err, "Failed to update the condition for the resource",
								"Deployment.Namespace", m.Namespace,
								"Deployment.Name", m.Name)
	
		return err
	}

	if msg != "" {
		r.Log.Error(err, msg,
								"Deployment.Namespace", m.Namespace,
								"Deployment.Name", m.Name)
	}

	return nil
}

/*****************************************************************************/

/*
 * Construct and return a list of labels for the deployment.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) labelsForApp(
								name string, pvc string) map[string]string {
	labels := map[string]string{
			"app.kubernetes.io/created-by": "verify-directory-operator",
			"app.kubernetes.io/part-of":    "verify-directory",
			"app.kubernetes.io/cr-name":    name}

	if pvc != "" {
		labels[PVCLabel] = pvc
	}

	return labels
}

/*****************************************************************************/

/*
 * Convert the parsed YAML into a hierarchical map.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) convertYaml(
					i interface{}) interface{} {
	switch x := i.(type) {

		case map[interface{}]interface{}:
			m2 := map[string]interface{}{}

			for k, v := range x {
				m2[k.(string)] = r.convertYaml(v)
			}

			return m2

		case []interface{}:
			for i, v := range x {
				x[i] = r.convertYaml(v)
			}

	}

    return i
}

/*****************************************************************************/

/*
 * Retrieve the value of the specified YAML.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) getYamlValue(
					i   interface{},
					key []string) interface{} {

	/*
	 * The first thing to do is cast the yaml to the correct type.
	 */

	v, ok := i.(map[string]interface{}) 

	if !ok {
		return nil
	}

	/*
	 * Retrieve the value of the current key.
	 */

	entry, ok := v[key[0]]

	if !ok {
		return nil
	}

	/*
	 * If we are at the end of the key we just return the value of
	 * the key.
	 */


	if len(key) == 1 {
		return entry
	}

	/*
	 * We are not at the end of the key and so we need to call getYamlValue
	 * again, moving to the next key.
	 */

	return r.getYamlValue(entry, key[1:])
}

/*****************************************************************************/

/*
 * The following function is used to retrieve the server port which is to
 * be used by the pods.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) getServerPort(
			ctx       context.Context, 
			directory *ibmv1.IBMSecurityVerifyDirectory) (int32, bool, error) {

	/*
	 * Retrieve the ConfigMap which contains the server configuration.
	 */

	name := directory.Spec.Pods.ConfigMap.Server.Name
	key  := directory.Spec.Pods.ConfigMap.Server.Key

	config := &corev1.ConfigMap{}
	err	   := r.Get(ctx, 
			types.NamespacedName{Name: name, Namespace: directory.Namespace}, 
			config)

	if err != nil {
		return 0, false, err
	}

	/*
	 * Parse the YAML configuration into a map.  Unfortunately it is not
	 * easy to parse YAML into a generic structure, and so after we have
	 * unmarshalled the data we want to iteratively convert the data into 
	 * a map of strings.
	 */

    var body interface{}
    if err := yaml.Unmarshal([]byte(config.Data[key]), &body); err != nil {
		return 0, false, err
    }

	body      = r.convertYaml(body)
	body, ok := body.(map[string]interface{})

	if ! ok {
		return 0, false, errors.New(
			"The server configuration cannot be parsed.")
	}

	/*
	 * Retrieve the general.ports.ldap configuration data.  
	 */

	var port   int32 = 9389
	var secure bool  = false

	ldap := r.getYamlValue(body, []string{"general","ports","ldap"})

	if ldap != nil {
		iport, ok := ldap.(int)

		if ! ok {
			return 0, false, errors.New(
						"The general.ports.ldap configuration is incorrect.")
		}

		port = int32(iport)

		if port == 0 {
			/*
			 * If the port is 0 it means that it has not been activated and
			 * so we need to use the ldaps port.
			 */

			secure = true
			port   = 9636

			ldaps := r.getYamlValue(body, []string{"general","ports","ldaps"})

			if ldaps != nil {
				iport, ok := ldaps.(int)

				if ! ok {
					return 0, false, errors.New(
						"The general.ports.ldaps configuration is incorrect.")
				}

				port = int32(iport)
			}
		}
	}

	r.Log.Info("Server networking information", "port", port, "is ssl", secure)

	return port, secure, nil
}

/*****************************************************************************/

/*
 * The following function is used to retrieve a list of existing pods for
 * the current deployment.  It will return a map of existing pods, indexed
 * on the name of the PVC.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) getExistingPods(
					ctx context.Context, 
					req ctrl.Request) (map[string]string, error) {

	pods := make(map[string]string)

	podList := &corev1.PodList{}

	opts := []client.ListOption{
		client.InNamespace(req.Namespace),
		client.MatchingLabels(r.labelsForApp(req.Name, "")),
	}

	err := r.List(ctx, podList, opts...)

	if err != nil {
 		r.Log.Error(err, "Failed to retrieve the existing pods",
								"Deployment.Namespace", req.Namespace,
								"Deployment.Name", req.Name)
	} else {
		for _, pod := range podList.Items {
			pods[pod.ObjectMeta.Labels[PVCLabel]] = pod.GetName()
		}
	}

	return pods, err 
}

/*****************************************************************************/

/*
 * Analyse the list of existing pods to determine which replicas need to be
 * deleted and which replicas need to be added.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) analyseExistingPods(
			directory *ibmv1.IBMSecurityVerifyDirectory,
			existing  map[string]string) ([]string, []string) {

	var toBeDeleted []string
	var toBeAdded   []string

	/*
	 * Create a map of the new PVCs from the document.
	 */

	var pvcs = make(map[string]bool)

	for _, pvcName := range directory.Spec.Replicas.PVCs {
		pvcs[pvcName] = true
	}

	/*
	 * Work out the entries to be deleted.  This consists of the existing
	 * replicas which don't appear in the current list of replicas.
	 */

	for key, _:= range existing {
		if _, ok := pvcs[key]; !ok {
			toBeDeleted = append(toBeDeleted, key)
		}
	}

	/*
	 * Work out the entries to be added.  This consists of those replicas
	 * which appear in the document which are not in the existing list of
	 * replicas.
	 */

	for key, _:= range pvcs {
		if _, ok := existing[key]; !ok {
			toBeAdded = append(toBeAdded, key)
		}
	}

	return toBeDeleted, toBeAdded
}

/*****************************************************************************/

/*
 * The following function is used to initialise a new replica.  
 */

func (r *IBMSecurityVerifyDirectoryReconciler) initializeReplica(
			ctx          context.Context, 
			directory    *ibmv1.IBMSecurityVerifyDirectory,
			principalPvc string,
			replicaPvc   string,
			existing     map[string]string) (error) {

	/*
	 * Processing:
	 *
	 *  seed the replica PVC with the PVC of the first replica
	 *  wait for the seed job to complete
	 *
	 *  for each existing pod:
	 *      r->createReplicationAgreement()
	 */

	// XXX: Multiple Replicas
	return nil
}

/*****************************************************************************/

/*
 * The following function is used to set up a new replication agreement.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) createReplicationAgreement(
			ctx       context.Context, 
			directory *ibmv1.IBMSecurityVerifyDirectory,
			pPort     int32,
			sourcePvc string,
			destPvc   string) (error) {

	// XXX: Multiple Replicas
	return nil
}

/*****************************************************************************/

/*
 * The following function is used to generate the pod name for the PVC.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) podName(
			directory  *ibmv1.IBMSecurityVerifyDirectory,
			pvcName    string) (string) {
	return strings.ToLower(fmt.Sprintf("%s-%s", directory.Name, pvcName))
}

/*****************************************************************************/

/*
 * Return a condition function that indicates whether the given pod is
 * currently running and available.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) isPodReady(
				ctx       context.Context,
				namespace string, 
				podName   string) wait.ConditionFunc {

	return func() (bool, error) {
		pod := &corev1.Pod{}
		err	:= r.Get(ctx, 
					types.NamespacedName{
						Name:	   podName,
						Namespace: namespace }, pod)

		if err != nil {
			return false, nil
		}

		switch pod.Status.Phase {
			case corev1.PodRunning:
				if pod.Status.ContainerStatuses[0].Ready {
					return true, nil
				}
			case corev1.PodFailed, corev1.PodSucceeded:
				return false, errors.New("The pod is no longer running")
		}

		return false, nil
	}
}

/*****************************************************************************/

/*
 * The following function is used to deploy a replica.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) deployReplica(
			ctx        context.Context, 
			directory  *ibmv1.IBMSecurityVerifyDirectory,
			serverPort int32,
			pvcName    string) (string, error) {

	podName := r.podName(directory, pvcName)

	/*
	 * Check if the pod already exists, and if one doesn't we create a 
	 * new one now.
	 */

	found := &corev1.Pod{}
	err   := r.Get(
					ctx,
					types.NamespacedName{
						Name:	  podName,
						Namespace: directory.Namespace},
					found)

	if err != nil {
		if ! kerrors.IsNotFound(err) {
			r.Log.Error(err, "Failed to retrieve the Pod resource")

			return "", err
		}
	}

	/*
	 * Create the pod.
	 */

	imageName := fmt.Sprintf("%s/verify-directory-server:%s", 
					directory.Spec.Pods.Image.Repo, 
					directory.Spec.Pods.Image.Label)

	/*
	 * The port which is exported by the deployment.
	 */

	ports := []corev1.ContainerPort {{
		Name:          "ldap",
		ContainerPort: serverPort,
		Protocol:      corev1.ProtocolTCP,
	}}

	/*
	 * The volume configuration.
	 */

	volumes := []corev1.Volume {
		{
			Name: "isvd-server-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: directory.Spec.Pods.ConfigMap.Server.Name,
					},
					Items: []corev1.KeyToPath{{
						Key:  directory.Spec.Pods.ConfigMap.Server.Key,
						Path: directory.Spec.Pods.ConfigMap.Server.Key,
					}},
				},
			},
		},
		{
			Name: "isvd-data",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: pvcName,
					ReadOnly:  false,
				},
			},
		},
	}

	volumeMounts := []corev1.VolumeMount {
		{
			Name:      "isvd-server-config",
			MountPath: "/var/isvd/config",
		},
		{
			Name:      "isvd-data",
			MountPath: "/var/isvd/data",
		},
	}

	/*
	 * Set up the environment variables.
	 */

	env := append(directory.Spec.Pods.Env, 
		corev1.EnvVar {
		   	Name: "YAML_CONFIG_FILE",
			Value: fmt.Sprintf("/var/isvd/config/%s", 
						directory.Spec.Pods.ConfigMap.Server.Key),
		},
		corev1.EnvVar {
		   	Name: "general.id",
			Value: podName,
		},
	)

	/*
	 * The liveness, and readiness probe definitions.
	 */

	livenessProbe := &corev1.Probe {
		InitialDelaySeconds: 2,
		PeriodSeconds:       10,
		ProbeHandler:        corev1.ProbeHandler {
			Exec: &corev1.ExecAction {
				Command: []string{
					"/sbin/health_check.sh",
					"livenessProbe",
				},
			},
		},
	}

	readinessProbe := &corev1.Probe {
		InitialDelaySeconds: 2,
		PeriodSeconds:       5,
		ProbeHandler:        corev1.ProbeHandler {
	 		Exec: &corev1.ExecAction {
				Command: []string{
					"/sbin/health_check.sh",
				},
			},
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: directory.Namespace,
			Labels:    r.labelsForApp(directory.Name, pvcName),
		},
		Spec: corev1.PodSpec{
			Volumes:            volumes,
			ImagePullSecrets:   directory.Spec.Pods.Image.ImagePullSecrets,
			ServiceAccountName: directory.Spec.Pods.ServiceAccountName,
			Hostname:           podName,
			Containers:         []corev1.Container{{
				Env:             env,
				EnvFrom:         directory.Spec.Pods.EnvFrom,
				Image:           imageName,
				ImagePullPolicy: directory.Spec.Pods.Image.ImagePullPolicy,
				LivenessProbe:   livenessProbe,
				Name:            podName,
				Ports:           ports,
				ReadinessProbe:  readinessProbe,
				Resources:       directory.Spec.Pods.Resources,
				VolumeMounts:    volumeMounts,
			}},
		},
	}

	/*
	 * Set the VerifyDirectory instance as the owner and controller
	 */

	ctrl.SetControllerReference(directory, pod, r.Scheme)

	r.Log.Info("Creating a new pod", "Pod.Namespace",
								pod.Namespace, "Pod.Name", pod.Name)

	err = r.Create(ctx, pod)

	if err != nil {
 		r.Log.Error(err, "Failed to create the new pod",
								"Pod.Namespace", pod.Namespace,
								"Pod.Name", pod.Name)

		return "", err
	}

	/*
	 * Wait for the pod to start.
	 */

	r.Log.Info("Waiting for the pod to become ready", "Pod.Namespace",
								pod.Namespace, "Pod.Name", pod.Name)

	err = wait.PollImmediate(time.Second, time.Duration(300) * time.Second, 
					r.isPodReady(ctx, pod.Namespace, pod.Name))

	if err != nil {
 		r.Log.Error(err, 
				"The pod failed to become ready within the allocated time.",
								"Pod.Namespace", pod.Namespace,
								"Pod.Name", pod.Name)

		return "", err
	}

	/*
	 * Create the service for the pod.
	 */

	err = r.createClusterService(ctx, directory, podName, serverPort, pvcName)

	if err != nil {
		return "", err
	}

	return podName, nil
}

/*****************************************************************************/

/*
 * The following function is used to deploy/redeploy the proxy.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) deployProxy(
			ctx        context.Context, 
			directory  *ibmv1.IBMSecurityVerifyDirectory,
			serverPort int32,
			secure     bool) (error) {

	/*
	 * Processing:
	 *   recreate the proxy configuration
	 *   if the proxy configuration has changed:
	 *     start/restart of the proxy
	 *     wait for the proxy to start
	 */

	// XXX: Proxy
	return nil
}

/*****************************************************************************/

/*
 * The following function is used to create a new service.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) createClusterService(
			ctx        context.Context, 
			directory  *ibmv1.IBMSecurityVerifyDirectory,
			podName    string,
			serverPort int32,
			pvcName    string) (error) {

	/*
	 * Initialise the service structure.
	 */

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: directory.Namespace,
			Labels:    r.labelsForApp(directory.Name, pvcName),
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: r.labelsForApp(directory.Name, pvcName),
			Ports:    []corev1.ServicePort{{
				Name:       podName,
				Protocol:   corev1.ProtocolTCP,
				Port:       serverPort,
				TargetPort: intstr.IntOrString {
					Type:   intstr.Int,
					IntVal: serverPort,
				},
			}},
		},
	}

	/*
	 * Create the service.
	 */

	r.Log.Info("Creating a new service for the pod", "Pod.Namespace",
								directory.Namespace, "Pod.Name", podName)

	err := r.Create(ctx, service)

	if err != nil {
 		r.Log.Error(err, "Failed to create the service for the pod",
								"Pod.Namespace", directory.Namespace,
								"Pod.Name", podName)

		return err
	}

	return nil
}

/*****************************************************************************/

/*
 * SetupWithManager sets up the controller with the Manager.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) SetupWithManager(
							mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ibmv1.IBMSecurityVerifyDirectory{}).
		Complete(r)
}

/*****************************************************************************/

