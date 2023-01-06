/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package controllers

/*****************************************************************************/

import (
//    appsv1 "k8s.io/api/apps/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"context"
//	"fmt"
    "time"

    "k8s.io/apimachinery/pkg/api/errors"
//    "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/go-logr/logr"

	ctrl  "sigs.k8s.io/controller-runtime"
	ibmv1 "github.com/ibm-security/verify-directory-operator/api/v1"
)

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
	err       := r.Get(ctx, req.NamespacedName, directory)

	if err != nil {

		if errors.IsNotFound(err) {
			/*
			 * The requested object was not found.  This means that it has
			 * been deleted.
  			 */

			err = r.DeleteServer(ctx, req)
		} else {
			/*
	  		 * There was an error reading the object - requeue the request.
			 */

			r.Log.Error(err, "Failed to get the VerifyDirectory resource")
		}

		return ctrl.Result{}, err
	}

	if directory.Generation == 1 {
		err = r.CreateServer(ctx, req, directory)
	} else {
		err = r.UpdateServer(ctx, req, directory)
	}

//	fmt.Printf("%+v\n", directory)

	/*
	 * Check if the deployment already exists, and if one doesn't we create a 
 	 * new one now.
 	 */

/*
	found := &appsv1.Deployment{}
	err    = r.Get(
	  				ctx,
	 				types.NamespacedName{
						Name:      directory.Name,
						Namespace: directory.Namespace},
					found)

	if err != nil {
		if errors.IsNotFound(err) {
 */
			/*
			 * A deployment does not already exist and so we create a new 
			 * deployment.
			 */
/*
			dep := r.deploymentForVerifyAccess(verifyaccess)

				r.Log.Info("Creating a new deployment", "Deployment.Namespace",
								dep.Namespace, "Deployment.Name", dep.Name)

				err = r.Create(ctx, dep)

				if err != nil {
					r.Log.Error(err, "Failed to create the new deployment",
								"Deployment.Namespace", dep.Namespace,
								"Deployment.Name", dep.Name)
				}
			}

		} else {
			r.Log.Error(err, "Failed to retrieve the Deployment resource")
		}

		r.setCondition(err, true, ctx, directory)

		return ctrl.Result{}, err
	}
 */

	/*
	 * The deployment already exists.  We now need to check to see if any
	 * of our CR fields have been updated which will require an update of
	 * the deployment.
	 */

/*
	r.Log.V(5).Info("Found a matching deployment",
	   							"Deployment.Namespace", found.Namespace,
	  							"Deployment.Name", found.Name)

	replicas := verifyaccess.Spec.Replicas

	if *found.Spec.Replicas != replicas {
		found.Spec.Replicas = &replicas

		err = r.Update(ctx, found)

		if err != nil {
			r.Log.Error(err, "Failed to update deployment",
								"Deployment.Namespace", found.Namespace,
								"Deployment.Name", found.Name)
		} else {
			r.Log.Info("Updated an existing deployment",
								"Deployment.Namespace", found.Namespace,
								"Deployment.Name", found.Name)
		}
	
		r.setCondition(err, false, ctx, verifyaccess)
	
		return ctrl.Result{}, err
	}
 */	
	return ctrl.Result{}, err
}

/*****************************************************************************/

/*
 * Delete a server from the environment.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) DeleteServer(
			ctx context.Context, req ctrl.Request) (err error) {

	r.Log.Info("Deleting a Verify Directory resource",
				"Namespace", req.Namespace,
				"Name",      req.Name)

	err = nil

	/*
	 * XXX: 
	 * Processing:
	 *   search for all matching pods
	 *
	 *   for each matching pod:
	 *     delete the pod
	 *
	 *   delete the proxy
	 */

	return
}

/*****************************************************************************/

/*
 * Create a server in the environment.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) CreateServer(
			ctx       context.Context, 
			req       ctrl.Request, 
			directory *ibmv1.IBMSecurityVerifyDirectory) (err error) {

	r.Log.Info("Creating a new Verify Directory resource",
				"Namespace", req.Namespace,
				"Name",      req.Name)

	err = nil

	/*
	 * XXX:
	 * Processing:
	 *   validate the proxy ConfigMap
	 *   validate the server ConfigMap and retrieve the port to be used
	 *
	 *   for each defined replica PVC:
	 *     if not the first replica:
	 *       set up the replication agreement on the first replica
	 *       seed the replica PVC with the PVC of the first replica
	 *       for each existing replica:
	 *         set up the replication agreement on the existing replica
	 *     create the pod
	 *     create the replica service definition
	 *
	 *   create the proxy pod
	 *   create the replica service definition
	 *
	 *   set the condition of the directory resource
	 */

	return
}

/*****************************************************************************/

/*
 * Update an existing server in the environment.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) UpdateServer(
			ctx       context.Context, 
			req       ctrl.Request, 
			directory *ibmv1.IBMSecurityVerifyDirectory) (err error) {

	r.Log.Info("Updating an existing Verify Directory resource",
				"Namespace", req.Namespace,
				"Name",      req.Name)

	err = nil

	/*
	 * XXX:
	 * Processing:
	 *   validate that only valid configuration has changed.
	 *
	 *   retrieve the list of existing pods
	 *   for each current pod:
	 *     if the pod is not available and is not being deleted:
	 *       return an error
	 *
	 *   for each current pod:
	 *     if pod PVC not in the list of current PVCs:
	 *       if pod is currently the master write:
	 *         return an error
	 *
	 *       for each pod:
	 *         remove replication agreement from pod
	 *       delete pod
	 *       delete pod service
	 *       remove pod from proxy configuration
	 *       
	 *   for each defined replica PVC:
	 *     if replica does not already exist:
	 *       set up the replication agreement on the first replica
	 *       stop the first replica
	 *       seed the replica PVC with the PVC of the first replica
	 *       for each existing replica:
	 *         set up the replication agreement on the existing replica
	 *       start the first replica
	 *       create the pod
	 *       create the replica service definition
	 *       add the pod to the proxy configuration
	 *
	 *    if the proxy configuration has changed:
	 *      perform a rolling restart of the proxy
	 *
	 *   set the condition of the directory resource
	 */

	return
}

/*****************************************************************************/

/*
 * The following function is used to wrap the logic which updates the
 * condition for a failure.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) setCondition(
				err      error,
			   	isCreate bool,
			  	ctx      context.Context,
			 	m        *ibmv1.IBMSecurityVerifyDirectory) error {

	var condReason  string
	var condMessage string
	
	if isCreate {
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
