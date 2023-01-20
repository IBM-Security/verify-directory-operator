/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package controllers

/*
 * This file contains the functions which are used by the controller to handle
 * the creation of a deployment/replica.
 */

/*****************************************************************************/

import (
	metav1  "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1  "k8s.io/api/core/v1"
	batchv1 "k8s.io/api/batch/v1"

	"fmt"
	"strconv"

	"github.com/ibm-security/verify-directory-operator/utils"

	ctrl "sigs.k8s.io/controller-runtime"
)

/*****************************************************************************/

/*
 * Create the required replicas for this deployment.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) createReplicas(
			h          *RequestHandle,
			existing   map[string]string,
			toBeAdded  []string) (map[string]string, error) {

	var err error = nil

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "createReplicas")...)

	/*
	 * Don't do anything here if there is nothing to be added.
	 */

	if len(toBeAdded) == 0 {
		return existing, nil
	}

	/*
	 * Work out the principal.  If we have any existing replicas the first
	 * of the existing replicas will be the principal, otherwise the first of
	 * the new replicas will be the principal.
	 */

	var principal string

	if len(existing) > 0 {

		for key, _ := range existing {
			principal = key
			break
		}

		r.Log.V(1).Info("Using a new principal.", 
			r.createLogParams(h, "Principal", principal)...)

	} else {
		principal, toBeAdded = toBeAdded[0], toBeAdded[1:]

		r.Log.Info("Creating the principal replica", 
					r.createLogParams(h, "pvc", principal)...)

		/*
		 * The principal doesn't currently exist and so we need to create
		 * the principal now.
		 */

		var pod string

		pod, err = r.deployReplica(h, principal)

		if err != nil {
			h.requeueOnError = false
			
			return nil, err
		}

		err = r.createClusterService(h, pod, h.config.port, principal)

		if err != nil {
			h.requeueOnError = false

			return nil, err
		}

		err = r.waitForPod(h, pod)

		if err != nil {
			h.requeueOnError = false

			return nil, err
		}

		existing[principal] = pod

		/*
		 * If there are no additional replicas to be added we can simply
		 * return now.
		 */

		if len(toBeAdded) == 0 {
			return existing, err
		}
	}

	/*
	 * Iterate over each PVC which is to be added, creating the replication
	 * agreement with the principal.
	 */

	for _, pvcName := range toBeAdded {
		err = r.createReplicationAgreement(
					h, principal, principal, pvcName)

		if err != nil {
			h.requeueOnError = false

			return nil, err
		}
	}

	/*
	 * Stop the principal.
	 */

	err = r.deleteReplica(h, principal, true)

	if err != nil {
		h.requeueOnError = false

		return nil, err
	}

	/*
	 * We should be able to completely specify the seed container configuration
	 * via environment variables, but a bug in the 10.0.0.0 release means
	 * that we can't set any 'seed' configuration entries via an environment
	 * variable.  To overcome this problem we need to create a ConfigMap
	 * which contains the seed configuration.
	 */

	seedConfigMapName := r.getSeedConfigMapName(h.directory)

	err = r.createConfigMap(h, seedConfigMapName, false,
			ConfigMapKey, "seed: \n  replica: \n    clean: true\n")

	if err != nil {
		h.requeueOnError = false

		return nil, err
	}

	/*
	 * Seed each of the new replicas.  We kick off the seed job for each of
	 * the new replicas, and then wait for all of the jobs to complete.
	 */

	for _, pvcName := range toBeAdded {
		err = r.seedReplica(h, principal, pvcName)

		if err != nil {
			h.requeueOnError = false

			r.deleteConfigMap(h, seedConfigMapName)

			return nil, err
		}
	}

	for _, pvcName := range toBeAdded {
		err = r.waitForJob(h, r.getSeedJobName(h.directory, pvcName))

		if err != nil {
			h.requeueOnError = false

			r.deleteConfigMap(h, seedConfigMapName)

			return nil, err
		}
	}

	/*
	 * Delete the temporary ConfigMap which was created.
	 */

	r.deleteConfigMap(h, seedConfigMapName)

	/*
	 * Now that the PVCs have been seeded with initial data we can now
	 * create and start each of the new replicas.  
	 */

	replicaPods := make(map[string]string)

	for _, pvcName := range toBeAdded {
		var podName string

		podName, err = r.deployReplica(h, pvcName)

		if err != nil {
			h.requeueOnError = false

			return nil, err
		}

		replicaPods[pvcName] = podName
		existing[pvcName]    = podName
	}

	for _, podName:= range replicaPods {
		err = r.waitForPod(h, podName)

		if err != nil {
			h.requeueOnError = false

			return nil, err
		}
	}

	/*
	 * The pods have each been started and so we now want to create the
	 * replication agreements between each new pod and all existing pods.
	 */

	for _, pvcName := range toBeAdded {
		err = r.createReplicationAgreements(h, principal, pvcName, existing)

		if err != nil {
			h.requeueOnError = false

			return nil, err
		}
	}

	/*
	 * Now we can create the cluster service for each of the new replicas.
	 */

	for pvcName, podName:= range replicaPods {
		err = r.createClusterService(h, podName, h.config.port, pvcName)

		if err != nil {
			h.requeueOnError = false

			return  nil, err
		}
	}

	/*
	 * Start the principal.
	 */

	principalPod, err := r.deployReplica(h, principal)

	if err != nil {
		h.requeueOnError = false

		return nil, err
	}

	err = r.createClusterService(h, principalPod, h.config.port, principal)

	if err != nil {
		h.requeueOnError = false

		return  nil, err
	}

	err = r.waitForPod(h, principalPod)

	if err != nil {
		h.requeueOnError = false

		return nil, err
	}

	return existing, nil
}

/*****************************************************************************/

/*
 * The following function is used to seed a new replica with the data from
 * the principal.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) seedReplica(
			h            *RequestHandle,
			principalPvc string,
			replicaPvc   string) (err error) {

	r.Log.V(1).Info("Entering a function", 
			r.createLogParams(h, "Function", "seedReplica",
				"Principal.PVC", principalPvc, "Replica.PVC", replicaPvc)...)

	/*
	 * Create the seed job which is used to seed the new replica with the
	 * data from the principal.
	 */

	jobName := r.getSeedJobName(h.directory, replicaPvc)

	imageName := fmt.Sprintf("%s/verify-directory-seed:%s", 
					h.directory.Spec.Pods.Image.Repo, 
					h.directory.Spec.Pods.Image.Label)

	/*
	 * The volume configuration.
	 */

	volumes := []corev1.Volume {
		{
			Name: "isvd-server-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: r.getSeedConfigMapName(h.directory),
					},
					Items: []corev1.KeyToPath{{
						Key:  ConfigMapKey,
						Path: ConfigMapKey,
					}},
				},
			},
		},
		{
			Name: "isvd-data",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: replicaPvc,
					ReadOnly:  false,
				},
			},
		},
		{
			Name: "isvd-principal",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: principalPvc,
					ReadOnly:  true,
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
		{
			Name:      "isvd-principal",
			MountPath: "/var/isvd/source",
		},
	}

	/*
	 * Set up the environment variables.
	 */

	env := append(h.directory.Spec.Pods.Env, 
		corev1.EnvVar {
		   	Name: "general.license.accept",
			Value: "limited",
		},
		corev1.EnvVar {
		   	Name: "general.license.key",
			Value: h.config.licenseKey,
		},
		corev1.EnvVar {
		   	Name: "YAML_CONFIG_FILE",
			Value: fmt.Sprintf("/var/isvd/config/%s", ConfigMapKey),
		},
	)

	/*
	 * Create the job.
	 */

	var completions  int32 = 1
	var backOffLimit int32 = 1
	var ttl          int32 = 30

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: h.directory.Namespace,
			Labels:    utils.LabelsForApp(h.directory.Name, replicaPvc),
		},
		Spec: batchv1.JobSpec{
			Completions:             &completions,
			TTLSecondsAfterFinished: &ttl,
			BackoffLimit:            &backOffLimit,
			Template:                corev1.PodTemplateSpec {
				Spec: corev1.PodSpec {
					Volumes:            volumes,
					ImagePullSecrets:   h.directory.Spec.Pods.Image.ImagePullSecrets,
					ServiceAccountName: h.directory.Spec.Pods.ServiceAccountName,
					RestartPolicy:      corev1.RestartPolicyNever,
					Containers:         []corev1.Container{{
						Env:             env,
						Image:           imageName,
						Name:            jobName,
						ImagePullPolicy: h.directory.Spec.Pods.Image.ImagePullPolicy,
						VolumeMounts:    volumeMounts,
					}},
				},
			},
		},
	}

	ctrl.SetControllerReference(h.directory, job, r.Scheme)

	r.Log.Info("Creating a new seed job", 
						r.createLogParams(h, "Job.Name", job.Name)...)

	r.Log.V(1).Info("Seed job details", 
				r.createLogParams(h, "Details", job)...)

	err = r.Create(h.ctx, job)

	if err != nil {
 		r.Log.Error(err, "Failed to create the new job",
						r.createLogParams(h, "Job.Name", job.Name)...)

		return 
	}

	return 
}

/*****************************************************************************/

/*
 * The following function is used to set up new replication agreements for 
 * the new replica.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) createReplicationAgreements(
			h            *RequestHandle,
			principalPvc string,
			replicaPvc   string,
			existing     map[string]string) (err error) {

	r.Log.V(1).Info("Entering a function", 
			r.createLogParams(h, "Function", "createReplicationAgreements",
				"Principal.PVC", principalPvc, "Replica.PVC", replicaPvc)...)

	/*
	 * Set up the replication agreement for every existing pod to this pod.
	 */

	for pvcName, _ := range existing {
		if pvcName != principalPvc && pvcName != replicaPvc {
			err = r.createReplicationAgreement(
					h, principalPvc, pvcName, replicaPvc)

			if err != nil {
				return
			}
		}
	}

	return
}

/*****************************************************************************/

/*
 * The following function is used to set up a new replication agreement.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) createReplicationAgreement(
			h            *RequestHandle, 
			principalPvc string,
			sourcePvc    string,
			destPvc      string) (error) {

	r.Log.Info(
		"Creating the replication agreement for the new replica", 
		r.createLogParams(h, "source", sourcePvc, "destination", destPvc)...)

	principalPod  := r.getReplicaPodName(h.directory, principalPvc)
	srcPod        := r.getReplicaPodName(h.directory, sourcePvc)
	dstPod        := r.getReplicaPodName(h.directory, destPvc)
	command       := []string{"isvd_manage_replica"}
	portStr       := strconv.Itoa(int(h.config.port))

	/*
	 * Let's play it safe and delete any pre-existing replication agreement
	 * for this replica.
	 */

	r.executeCommand(
			h, srcPod, []string{"isvd_manage_replica", "-r", "-i", dstPod})

	/*
	 * Now we can add in the replication agreement.
	 */

	if principalPod == srcPod {
		command = append(command, "-ap",
            "-h",  dstPod,
			"-p",  portStr,
			"-i",  dstPod,
            "-ph", srcPod,
			"-pp", portStr)
	} else {
		command = append(command, "-ar",
			"-h", dstPod,
			"-p", portStr,
			"-i", dstPod,
			"-s", principalPod)
	}

	if h.config.secure {
		command = append(command, "-z")
	}

	return r.executeCommand(h, srcPod, command)
}

/*****************************************************************************/

/*
 * The following function is used to deploy a replica.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) deployReplica(
			h       *RequestHandle,
			pvcName string) (string, error) {

	r.Log.V(1).Info("Entering a function", 
		r.createLogParams(h, "Function", "deployReplica", "PVC", pvcName)...)

	podName := r.getReplicaPodName(h.directory, pvcName)

	imageName := fmt.Sprintf("%s/verify-directory-server:%s", 
					h.directory.Spec.Pods.Image.Repo, 
					h.directory.Spec.Pods.Image.Label)

	/*
	 * The port which is exported by the deployment.
	 */

	ports := []corev1.ContainerPort {{
		Name:          "ldap",
		ContainerPort: h.config.port,
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
						Name: h.directory.Spec.Pods.ConfigMap.Server.Name,
					},
					Items: []corev1.KeyToPath{{
						Key:  h.directory.Spec.Pods.ConfigMap.Server.Key,
						Path: h.directory.Spec.Pods.ConfigMap.Server.Key,
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

	env := append(h.directory.Spec.Pods.Env, 
		corev1.EnvVar {
		   	Name: "YAML_CONFIG_FILE",
			Value: fmt.Sprintf("/var/isvd/config/%s", 
						h.directory.Spec.Pods.ConfigMap.Server.Key),
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
		InitialDelaySeconds: 4,
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
			Namespace: h.directory.Namespace,
			Labels:    utils.LabelsForApp(h.directory.Name, pvcName),
		},
		Spec: corev1.PodSpec{
			Volumes:            volumes,
			ImagePullSecrets:   h.directory.Spec.Pods.Image.ImagePullSecrets,
			ServiceAccountName: h.directory.Spec.Pods.ServiceAccountName,
			Hostname:           podName,
			Containers:         []corev1.Container{{
				Env:             env,
				EnvFrom:         h.directory.Spec.Pods.EnvFrom,
				Image:           imageName,
				ImagePullPolicy: h.directory.Spec.Pods.Image.ImagePullPolicy,
				LivenessProbe:   livenessProbe,
				Name:            podName,
				Ports:           ports,
				ReadinessProbe:  readinessProbe,
				Resources:       h.directory.Spec.Pods.Resources,
				VolumeMounts:    volumeMounts,
			}},
		},
	}

	ctrl.SetControllerReference(h.directory, pod, r.Scheme)

	/*
	 * Create the pod.
	 */

	r.Log.Info("Creating a new pod", 
						r.createLogParams(h, "Pod.Name", pod.Name)...)

	r.Log.V(1).Info("Pod details", 
				r.createLogParams(h, "Details", pod)...)

	err := r.Create(h.ctx, pod)

	if err != nil {
 		r.Log.Error(err, "Failed to create the new pod",
						r.createLogParams(h, "Pod.Name", pod.Name)...)

		return "", err
	}

	return podName, nil
}

/*****************************************************************************/

