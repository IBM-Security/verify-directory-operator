/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package controllers

/*
 * This file contains the functions which are used by the controller to handle
 * the deletion of a deployment/replica.
 */

/*****************************************************************************/

import (
	metav1  "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1  "k8s.io/api/core/v1"
	batchv1 "k8s.io/api/batch/v1"

	"strconv"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

/*****************************************************************************/

/*
 * Delete a server from the environment.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) deleteDeployment(
			h *RequestHandle) (err error) {

	r.Log.Info("Deleting a Verify Directory resource",
					r.createLogParams(h)...)

	err = nil

	opts    := []client.DeleteAllOfOption{
		client.InNamespace(h.req.Namespace),
		client.MatchingLabels(r.labelsForApp(h.req.Name, "")),
	}

	/*
	 * Delete all of the services for the deployment.
	 */

	service := &corev1.Service{}

	err = r.DeleteAllOf(h.ctx, service, opts...)

	if err != nil {
		return 
	}

	/*
	 * Delete all of the pods for the deployment.
	 */

	pod := &corev1.Pod{}

	err = r.DeleteAllOf(h.ctx, pod, opts...)

	if err != nil {
		return 
	}

	/*
	 * Delete all of the Jobs for the deployment.
	 */

	job     := &batchv1.Job{}
	jobOpts := []client.DeleteAllOfOption{
		client.InNamespace(h.req.Namespace),
		client.MatchingLabels(r.labelsForApp(h.req.Name, "")),
		client.PropagationPolicy(metav1.DeletePropagationBackground),
	}

	err = r.DeleteAllOf(h.ctx, job, jobOpts...)

	if err != nil {
		return 
	}

	/*
	 * Delete all of the ConfigMaps for the deployment.
	 */

	configMap := &corev1.ConfigMap{}

	err = r.DeleteAllOf(h.ctx, configMap, opts...)

	if err != nil {
		return 
	}

	return
}

/*****************************************************************************/

/*
 * Delete the replicas for this deployment which are no longer required.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) deleteReplicas(
			h           *RequestHandle,
			existing    map[string]string,
			toBeDeleted []string) (err error) {

	err = nil

	/*
	 * Create a map of the to-be-deleted PVCs.
	 */

	var toBeDeletedPvcs = make(map[string]bool)

	for _, pvcName := range toBeDeleted {
		toBeDeletedPvcs[pvcName] = true
	}

	/*
	 * Process each of the replicas which are to be deleted.
	 */

	for idx, pvcName := range toBeDeleted {
		r.Log.Info("Deleting the replica", 
			r.createLogParams(h, 
				strconv.FormatInt(int64(idx), 10), pvcName)...)

		/*
		 * Ensure that this replica is not the write-master according to the
		 * proxy.
		 */

		// XXX: Proxy

		/*
		 * Remove the replication agreement from each of the existing
		 * replicas.
		 */

		id := r.getReplicaPodName(h.directory, pvcName)
		
		for pvc, podName := range existing {
			if _, ok := toBeDeletedPvcs[pvc]; !ok {
				r.deleteReplicationAgreement(h, podName, id)
			}
		}

		/*
		 * Delete the pod and service.
		 */

		err = r.deleteReplica(h, pvcName, true)

		if err != nil {
			return
		}
	}

	return
}

/*****************************************************************************/

/*
 * The following function is used to delete a replica.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) deleteReplica(
			h          *RequestHandle,
			pvcName    string,
			waitOnPod  bool) (err error)  {

	opts := []client.DeleteAllOfOption{
		client.InNamespace(h.req.Namespace),
		client.MatchingLabels(r.labelsForApp(h.req.Name, pvcName)),
	}

	/*
	 * Delete the service.
	 */

	service := &corev1.Service{}

	err = r.DeleteAllOf(h.ctx, service, opts...)

	if err != nil {
		return 
	}

	/*
	 * Delete the pod.
	 */

	pod := &corev1.Pod{}

	err = r.DeleteAllOf(h.ctx, pod, opts...)

	if err != nil {
		return 
	}

	if waitOnPod {
		/*
		 * Wait for the pod to stop.
		 */

		podName := r.getReplicaPodName(h.directory, pvcName)

		r.Log.Info("Waiting for the pod to stop", 
					r.createLogParams(h, "Pod.Name", podName)...)

		err = wait.PollImmediate(time.Second, time.Duration(300) * time.Second, 
					r.isPodOpComplete(h.ctx, h.req.Namespace, podName, false))

		if err != nil {
			r.Log.Error(err, 
				"The pod failed to stop within the allocated time.",
				r.createLogParams(h, "Pod.Name", podName)...)

			return
		}
	}

	return
}

/*****************************************************************************/

/*
 * The following function is used to delete an existing replication agreement.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) deleteReplicationAgreement(
			h            *RequestHandle,
			podName      string,
			replicaId    string) {

	r.Log.Info(
		"Deleting an existing replication agreement", 
		r.createLogParams(h, "Pod.Name", podName, "Replica.Id", replicaId)...)

	r.executeCommand(h, podName, 
		[]string{"isvd_manage_replica", "-r", "-i", replicaId})
}

/*****************************************************************************/

