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
	corev1  "k8s.io/api/core/v1"
	metav1  "k8s.io/apimachinery/pkg/apis/meta/v1"

	"strconv"
	"time"

	"github.com/ibm-security/verify-directory-operator/utils"

	"k8s.io/apimachinery/pkg/util/wait"
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

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "deleteReplica",
						"PVC.Name", pvcName, "Waiting", waitOnPod)...)	

	podName := r.getReplicaPodName(h.directory, pvcName)

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

	if err != nil {
		return 
	}

	/*
	 * Delete the pod.
	 */

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: h.directory.Namespace,
			Labels:    utils.LabelsForApp(h.directory.Name, pvcName),
		},
	}

	r.Log.V(1).Info("Deleting a pod.", "Pod", pod)

	err = r.Delete(h.ctx, pod)

	if err != nil {
		return 
	}

	if waitOnPod {
		/*
		 * Wait for the pod to stop.
		 */

		r.Log.Info("Waiting for the pod to stop", 
					r.createLogParams(h, "Pod.Name", podName)...)

		err = wait.PollImmediate(time.Second, time.Duration(300) * time.Second, 
					r.isPodOpComplete(h, podName, false))

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

