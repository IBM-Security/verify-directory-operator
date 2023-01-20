/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package controllers

/*****************************************************************************/

import (
	metav1  "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1  "k8s.io/api/core/v1"

	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/api/meta"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/go-logr/logr"
	"github.com/ibm-security/verify-directory-operator/utils"

	ctrl  "sigs.k8s.io/controller-runtime"
	ibmv1 "github.com/ibm-security/verify-directory-operator/api/v1"
)

/*****************************************************************************/

/*
 * Some constants...
 */

const ConfigMapKey = "config.yaml"

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
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;create;delete
//+kubebuilder:rbac:groups=core,resources=pods/exec,verbs=create
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;delete
//+kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;delete
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;delete
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch

/*****************************************************************************/

/*
 * The following structure contains the server configuration which is required
 * by the operator.
 */

type ServerConfig struct {
	port       int32
	secure     bool
	licenseKey string
	adminDn    string
	adminPwd   string
	suffixes   []string
}

/*
 * The following structure is used to define a request handle for the operator.
 * The request handle will contain the information which is common across a
 * single request.
 */

type RequestHandle struct {
	ctx            context.Context
	req            ctrl.Request
	directory      *ibmv1.IBMSecurityVerifyDirectory
	requeueOnError bool
	config         ServerConfig
}

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

	/*
	 * Construct the request handle.
	 */

	h := RequestHandle{
		ctx:            ctx,
		req:            req,
		directory:      &ibmv1.IBMSecurityVerifyDirectory{},
		requeueOnError: true,
	}

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(&h, "Function", "Reconcile")...)

	/*
	 * Fetch the definition document.
	 */

	err	:= r.Get(ctx, req.NamespacedName, h.directory)

	if err != nil {

		if errors.IsNotFound(err) {
			/*
			 * The requested object was not found.  This means that it has
			 * been deleted.
  			 */

			r.Log.Info("Resource not found due to it having been deleted", 
								r.createLogParams(&h)...)

			err = nil
		} else {
			/*
	  		 * There was an error reading the object - requeue the request.
			 */

			r.Log.Error(err, "Failed to get the VerifyDirectory resource",
					r.createLogParams(&h)...)
		}

		return ctrl.Result{}, r.reconcileError(&h, err)
	}

	r.Log.V(1).Info("Reconciling a document", 
				r.createLogParams(&h, "Document", h.directory)...)

	/*
	 * We now need to potentially create or update the deployment.
	 */

	/*
	 * Retrieve the list of existing pods for the deployment.
	 */

	existing, err := r.getExistingPods(&h)

	if err != nil {
		r.setCondition(err, &h,
							"Failed to retrieve the list of existing pods.")

		return ctrl.Result{}, r.reconcileError(&h, err)
	}

	r.Log.Info("Existing pods", r.createLogParams(&h, "Pods", existing)...)

	/*
	 * Work out the list of replicas to be deleted, and the list of
	 * replicas to be added.
	 */

	toBeDeleted, toBeAdded := r.analyseExistingPods(&h, existing)

	r.Log.Info("Updates required",
		r.createLogParams(&h, 
			"to be deleted", toBeDeleted,
			"to be added", toBeAdded)...)

	if len(toBeDeleted) == 0 && len(toBeAdded) == 0 {
		return ctrl.Result{}, nil
	}

	/*
	 * Mark the deployment as in-progress.
	 */

	condition := metav1.Condition{
		Type:    "InProgress",
		Reason:  "DeploymentProgress",
		Message: "The deployment is being processed.",
		Status:  metav1.ConditionTrue,
	}

	meta.SetStatusCondition(&h.directory.Status.Conditions, condition)

	if err := r.Status().Update(h.ctx, h.directory); err != nil {
		r.Log.Error(err, "Failed to update the condition for the resource",
						r.createLogParams(&h)...)
	
		return ctrl.Result{}, r.reconcileError(&h, err)
	}

	/*
	 * Get the configuration to be used by the server.
	 */

	err = r.getServerConfig(&h)

	if err != nil {
		r.setCondition(err, &h,
			"Failed to obtain the server information from the ConfigMap.")

		return ctrl.Result{}, r.reconcileError(&h, err)
	}

	/*
	 * Create the new replicas.
	 */

	existing, err = r.createReplicas(&h, existing, toBeAdded)

	if err != nil {
		r.setCondition(err, &h,
					"Failed to create the new replicas.")

		return ctrl.Result{}, r.reconcileError(&h, err)
	}

	/*
	 * Now that we have created the replicas we need to deploy the
	 * front-end proxy.
	 */

	err = r.deployProxy(&h)

	if err != nil {
		r.setCondition(err, &h, "Failed to deploy the proxy.")

		return ctrl.Result{}, r.reconcileError(&h, err)
	}

	/*
	 * Delete the replicas which have been removed from the deployment.
	 */

	err = r.deleteReplicas(&h, existing, toBeDeleted)

	if err != nil {
		r.setCondition(err, &h, "Failed to delete the obsolete replicas.")

		return ctrl.Result{}, r.reconcileError(&h, err)
	}

	/*
	 * Set the condition of the document.
	 */

	r.Log.Info("Reconciled the document", r.createLogParams(&h)...) 

	r.setCondition(err, &h, "")

	return ctrl.Result{}, r.reconcileError(&h, err)
}

/*****************************************************************************/

/*
 * The following function will return the specified error if the requeue
 * capability is requested, otherwise it will return nil.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) reconcileError(
				h   *RequestHandle,
				err error) (error) {

	if h.requeueOnError {
		return err
	} else {
		return nil
	}
}

/*****************************************************************************/

/*
 * The following function is used to wrap the logic which updates the
 * condition of the deployment.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) setCondition(
				err error,
				h   *RequestHandle,
				msg string) error {

	progressCondition := metav1.Condition{
		Type:    "InProgress",
		Reason:  "DeploymentProgress",
		Message: "The deployment has been processed.",
		Status:  metav1.ConditionFalse,
	}

	meta.SetStatusCondition(&h.directory.Status.Conditions, progressCondition)

	condition := metav1.Condition{
		Type: "Available",
	}

	if h.directory.Generation == 1 {
		condition.Reason  = "DeploymentCreated"
		condition.Message = "The deployment has been created."
	} else {
		condition.Reason  = "DeploymentUpdated"
		condition.Message = "The deployment has been updated."
	}

	if err != nil {
		condition.Message = err.Error()
		condition.Status  = metav1.ConditionFalse
	} else {
		condition.Status  = metav1.ConditionTrue
	}

	r.Log.V(1).Info("Setting a condition", 
				r.createLogParams(h, "Condition", condition)...)

	meta.SetStatusCondition(&h.directory.Status.Conditions, condition)

	if err := r.Status().Update(h.ctx, h.directory); err != nil {
		r.Log.Error(err, "Failed to update the condition for the resource",
						r.createLogParams(h)...)
	
		return err
	}

	if msg != "" {
		r.Log.Error(err, msg, r.createLogParams(h)...)
	}

	return nil
}

/*****************************************************************************/

/*
 * The following function is used to retrieve a list of existing pods for
 * the current deployment.  It will return a map of existing pods, indexed
 * on the name of the PVC.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) getExistingPods(
					h *RequestHandle) (map[string]string, error) {

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "getExistingPods")...)

	pods := make(map[string]string)

	podList := &corev1.PodList{}

	opts := []client.ListOption{
		client.InNamespace(h.req.Namespace),
		client.MatchingLabels(utils.LabelsForApp(h.req.Name, "")),
	}

	err := r.List(h.ctx, podList, opts...)

	if err != nil {
 		r.Log.Error(err, "Failed to retrieve the existing pods",
						r.createLogParams(h)...)
	} else {
		for _, pod := range podList.Items {
			pods[pod.ObjectMeta.Labels[utils.PVCLabel]] = pod.GetName()
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
			h        *RequestHandle,
			existing map[string]string) ([]string, []string) {

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "analyseExistingPods",
						"Existing Pods", existing)...)

	var toBeDeleted []string
	var toBeAdded   []string

	/*
	 * Create a map of the new PVCs from the document.
	 */

	var pvcs = make(map[string]bool)

	for _, pvcName := range h.directory.Spec.Replicas.PVCs {
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

	for _, pvc := range h.directory.Spec.Replicas.PVCs {
		if _, ok := existing[pvc]; !ok {
			toBeAdded = append(toBeAdded, pvc)
		}
	}

	return toBeDeleted, toBeAdded
}

/*****************************************************************************/

/*
 * This function will create the logging parameters for a request.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) createLogParams(
			h *RequestHandle, extras ...interface{}) []interface{} {

	params := []interface{}{
				"Deployment.Namespace", h.req.Namespace,
				"Deployment.Name",      h.req.Name,
			}

	for _, extra := range extras {
		params = append(params, extra)
	}

	return params
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

