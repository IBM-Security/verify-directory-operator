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
	appsv1  "k8s.io/api/apps/v1"
	corev1  "k8s.io/api/core/v1"
	metav1  "k8s.io/apimachinery/pkg/apis/meta/v1"

	"strconv"
	"time"

	"github.com/ibm-security/verify-directory-operator/utils"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/api/errors"
)

/*****************************************************************************/

/*
 * Delete the replicas for this deployment which are no longer required.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) deleteReplicas(
			h           *RequestHandle,
			existing    map[string]string,
			toBeDeleted []string) (err error) {

	err = nil

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "deleteReplicas")...)

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
		 * Remove the replication agreement from each of the existing
		 * replicas.
		 */

		id := r.getReplicaPodName(h.directory, pvcName)
		name := r.getReplicaSetPodName(h, id)
		
		for pvc, _ := range existing {
			if _, ok := toBeDeletedPvcs[pvc]; !ok {
				r.deleteReplicationAgreement(h, name, id)
			}
		}

		/*
		 * Delete the pod and service.
		 */

		err = r.deleteReplica(h, pvcName)

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
			h       *RequestHandle,
			pvcName string) (err error) {

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "deleteReplica",
						"PVC.Name", pvcName)...)

	podName := r.getReplicaPodName(h.directory, pvcName)
	name := r.getReplicaSetPodName(h, podName)

	/*
	 * Set the labels for the pod.
	 */

	/*labels := map[string]string{
		"app.kubernetes.io/kind":    "IBMSecurityVerifyDirectory",
		"app.kubernetes.io/cr-name": podName,
	}*/
		
	/*
	 * Delete the service.
	 */

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: h.directory.Namespace,
			Labels:    utils.LabelsForApp(h.directory.Name, pvcName),
		},
	}

	r.Log.V(1).Info("Deleting a service.", "Service", service)

	err = r.Delete(h.ctx, service)

	if err != nil && !errors.IsNotFound(err) {
		return
	}

	/*
	 * Delete the pod.
	 */

	rep := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: h.directory.Namespace,
			Labels:    utils.LabelsForApp(h.directory.Name, pvcName),
		},
	}

	r.Log.V(1).Info("Deleting a pod.", "ReplicaSet.Name", podName)

	err = r.Delete(h.ctx, rep)

	if err != nil && !errors.IsNotFound(err) {
		return
	}

	/*
	 * Wait for the pod to stop.
	 */

	r.Log.Info("Waiting for the pod to stop", 
					r.createLogParams(h, "Pod.Name", name)...)

	err = wait.PollImmediate(time.Second, time.Duration(300) * time.Second, 
					r.isPodOpComplete(h, name, false))

	if err != nil {
		r.Log.Error(err, 
			"The pod failed to stop within the allocated time.",
			r.createLogParams(h, "Pod.Name", name)...)

		return
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

