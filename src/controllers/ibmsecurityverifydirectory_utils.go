/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package controllers

/*
 * This file contains the some utility style functions which are used by the 
 * controller.
 */

/*****************************************************************************/

import (
	metav1  "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1  "k8s.io/api/core/v1"
	batchv1 "k8s.io/api/batch/v1"

	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/ibm-security/verify-directory-operator/utils"

	ibmv1 "github.com/ibm-security/verify-directory-operator/api/v1"
)

/*****************************************************************************/

/*
 * The following function is used to generate the pod name for the PVC.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) getReplicaPodName(
			directory  *ibmv1.IBMSecurityVerifyDirectory,
			pvcName    string) (string) {
	return strings.ToLower(fmt.Sprintf("%s-%s", directory.Name, pvcName))
}

/*****************************************************************************/

/*
 * The following function is used to generate the ConfigMap name for the 
 * directory deployment.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) getSeedConfigMapName(
			directory  *ibmv1.IBMSecurityVerifyDirectory) (string) {
	return strings.ToLower(fmt.Sprintf("%s-seed", directory.Name))
}

/*****************************************************************************/

/*
 * The following function will create the name of the job which is used to
 * seed the replica.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) getSeedJobName(
			directory    *ibmv1.IBMSecurityVerifyDirectory,
			pvc          string) (string) {
	return fmt.Sprintf("%s-seed", r.getReplicaPodName(directory, pvc))
}

/*****************************************************************************/

/*
 * The following function is used to create a ConfigMap with the specified
 * data.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) createConfigMap(
			h            *RequestHandle,
			mapName      string,
			key          string,
			value        string) (err error) {

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "createConfigMap",
						"Map.Name", mapName, "Key", key,
						"Value", value)...)	

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      mapName,
			Namespace: h.directory.Namespace,
			Labels:    utils.LabelsForApp(h.directory.Name, mapName),
		},
		Data: map[string]string{
			key: value,
		},
	}

	r.Log.Info("Creating a new ConfigMap", 
						r.createLogParams(h, "ConfigMap.Name", mapName)...)

	ctrl.SetControllerReference(h.directory, configMap, r.Scheme)

	err = r.Create(h.ctx, configMap)

	if err != nil {
		if k8serrors.IsAlreadyExists(err) {
			r.Log.Info("Updating an existing ConfigMap", 
						r.createLogParams(h, "ConfigMap.Name", mapName)...)

			err = r.Update(h.ctx, configMap)

			if err != nil {
				r.Log.Error(err, "Failed to update the ConfigMap",
						r.createLogParams(h, "ConfigMap.Name", mapName)...)

				return
			}
		} else {
			r.Log.Error(err, "Failed to create the new ConfigMap",
						r.createLogParams(h, "ConfigMap.Name", mapName)...)

			return
		}
	}

	return
}

/*****************************************************************************/

/*
 * The following function is used to delete the specified config map.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) deleteConfigMap(
			h            *RequestHandle,
			mapName      string) (err error) {

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "deleteConfigMap",
						"Map.Name", mapName)...)	

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      mapName,
			Namespace: h.directory.Namespace,
			Labels:    utils.LabelsForApp(h.directory.Name, mapName),
		},
	}

	err = r.Delete(h.ctx, configMap)

	if err != nil {
		h.requeueOnError = false

		return 
	}

	return
}


/*****************************************************************************/

/*
 * Return a condition function that indicates whether the given job has
 * completed.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) isJobComplete(
				h         *RequestHandle,
				podName   string) wait.ConditionFunc {

	return func() (bool, error) {
		job := &batchv1.Job{}
		err	:= r.Get(h.ctx, 
					types.NamespacedName{
						Name:	   podName,
						Namespace: h.directory.Namespace }, job)

		r.Log.V(1).Info("Checking if a job has completed", 
				r.createLogParams(h, "Job", job)...)

		if err != nil {
			return false, nil
		}

		if job.Status.Failed > 0 {
			return true, errors.New("The job failed!")
		}

		if job.Status.Succeeded > 0 {
			return true, nil
		}

		return false, nil
	}
}

/*****************************************************************************/

/*
 * Return a condition function that indicates whether the given pod is
 * currently running and available.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) isPodOpComplete(
				h            *RequestHandle,
				podName      string,
				waitForStart bool) wait.ConditionFunc {

	return func() (bool, error) {
		pod := &corev1.Pod{}
		err	:= r.Get(h.ctx, 
					types.NamespacedName{
						Name:	   podName,
						Namespace: h.directory.Namespace }, pod)

		r.Log.V(1).Info("Checking if a Pod operation has completed", 
			r.createLogParams(h, "Wait.For.Start", waitForStart, "Pod", pod)...)

		/*
		 * If we are waiting for the pod to stop we can return immediately
		 * based on whether the pod was found or not.
		 */

		if (!waitForStart) {
			if err == nil {
				return false, nil
			} else {
				return true, nil
			}
		}

		/*
		 * We are waiting for the pod to start and so we need to check the
		 * current status of the pod.
		 */

		if err != nil {
			return false, nil
		}

		switch pod.Status.Phase {
			case corev1.PodRunning:
				if pod.Status.ContainerStatuses[0].Ready {
					return true, nil
				}
			case corev1.PodFailed, corev1.PodSucceeded:
				return true, errors.New("The pod is no longer running")
		}

		return false, nil
	}
}

/*****************************************************************************/

/*
 * The following function is used to wait for the specified pod to start
 * and be ready.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) waitForPod(
				h    *RequestHandle,
				name string) (err error) {

	r.Log.Info("Waiting up to 10 minutes for the pod to become ready", 
					r.createLogParams(h, "Pod.Name", name)...)

	err = wait.PollImmediate(time.Second, time.Duration(600) * time.Second, 
					r.isPodOpComplete(h, name, true))

	if err != nil {
 		r.Log.Error(err, 
				"The pod failed to become ready within the allocated time.",
				r.createLogParams(h, "Pod.Name", name)...)

		return 
	}

	return
}

/*****************************************************************************/

/*
 * The following function is used to wait for the specified job to complete.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) waitForJob(
				h    *RequestHandle,
				name string) (err error) {

	/*
	 * Wait for the job to finish.
	 */

	r.Log.Info("Waiting up to 10 minutes for the job to finish", 
					r.createLogParams(h, "Job.Name", name)...)

	err = wait.PollImmediate(time.Second, time.Duration(600) * time.Second, 
					r.isJobComplete(h, name))

	if err != nil {
 		r.Log.Error(err, 
				"The job failed to complete within the allocated time.",
				r.createLogParams(h, "Job.Name", name)...)

		return 
	}

	return
}

/*****************************************************************************/

/*
 * The following function is used to create a new service.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) createClusterService(
			h          *RequestHandle,
			podName    string,
			serverPort int32,
			pvcName    string) (error) {

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "createClusterService",
						"Pod.Name", podName, "Port", serverPort,
						"PVC.Name", pvcName)...)	

	/*
	 * Initialise the service structure.
	 */

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: h.directory.Namespace,
			Labels:    utils.LabelsForApp(h.directory.Name, pvcName),
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: utils.LabelsForApp(h.directory.Name, pvcName),
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

	ctrl.SetControllerReference(h.directory, service, r.Scheme)

	/*
	 * Create the service.
	 */

	r.Log.Info("Creating a new service for the pod", 
				r.createLogParams(h, "Pod.Name", podName)...)

	r.Log.V(1).Info("Service details", 
			r.createLogParams(h, "Service", service)...)

	err := r.Create(h.ctx, service)

	if err != nil {
 		r.Log.Error(err, "Failed to create the service for the pod",
				r.createLogParams(h, "Pod.Name", podName)...)

		return err
	}

	return nil
}

/*****************************************************************************/

/*
 * The following function is used to execute a command on the specified
 * pod.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) executeCommand(
				h       *RequestHandle,
				pod     string,
				command []string) error {

	r.Log.Info("Executing a command", 
			r.createLogParams(h, "Pod", pod, "Command", command)...)

	/*
	 * Create a client which can be used.
	 */

	kubeConfig := ctrl.GetConfigOrDie()
	kubeClient := kubernetes.NewForConfigOrDie(kubeConfig)

	/*
	 * Construct the request.
	 */

	request := kubeClient.
		CoreV1().
		RESTClient().
		Post().
		Resource("pods").
		Namespace(h.directory.Namespace).
		Name(pod).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command:   command,
			Stdout:    true,
			Stderr:    true,
			TTY:       true,
		}, scheme.ParameterCodec)

	/*
	 * Execute the command.
	 */

	exec, err := remotecommand.NewSPDYExecutor(
								kubeConfig, "POST", request.URL())
	if err != nil {
		r.Log.Error(err, "Failed to execute a command!", 
				r.createLogParams(h, "command", command)...)

		return err
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if err := exec.Stream(remotecommand.StreamOptions{
					Stdout: &stdout, Stderr: &stderr}); err != nil {
		r.Log.Error(err, "Failed to execute a command!", 
				r.createLogParams(h, "command", command, 
					"stdout", stdout.String(), "stderr", stderr.String())...)

		return err
	}

	r.Log.V(1).Info("Command Results", 
			r.createLogParams(h, "Pod", pod, "Command", command,
				"stdout", stdout.String(), "stderr", stderr.String())...)

	return nil
}

/*****************************************************************************/


