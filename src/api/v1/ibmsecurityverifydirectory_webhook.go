/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package v1

/*****************************************************************************/

import (
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
    "sigs.k8s.io/controller-runtime/pkg/client"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

/*****************************************************************************/

/*
 * The following log object is for logging in this package.
 */

var logger = logf.Log.WithName("ibmsecurityverifydirectory-resource")

/*
 * The following object allows us to access the Kubernetes API.
 */

var k8s_client client.Client

/*****************************************************************************/

/*
 * The following function is used to set up the Web hook with the Manager.
 */

func (r *IBMSecurityVerifyDirectory) SetupWebhookWithManager(
					mgr ctrl.Manager) error {

    k8s_client = mgr.GetClient()

	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

/*****************************************************************************/

//+kubebuilder:webhook:path=/mutate-ibm-com-v1-ibmsecurityverifydirectory,mutating=true,failurePolicy=fail,sideEffects=None,groups=ibm.com,resources=ibmsecurityverifydirectories,verbs=create;update,versions=v1,name=mibmsecurityverifydirectory.kb.io,admissionReviewVersions=v1

var _ webhook.Defaulter = &IBMSecurityVerifyDirectory{}

/*
 * The following function is used to add default values into the document.
 * This is currently a no-op for this operator.
 */

func (r *IBMSecurityVerifyDirectory) Default() {
}

/*****************************************************************************/

//+kubebuilder:webhook:path=/validate-ibm-com-v1-ibmsecurityverifydirectory,mutating=false,failurePolicy=fail,sideEffects=None,groups=ibm.com,resources=ibmsecurityverifydirectories,verbs=create;update,versions=v1,name=vibmsecurityverifydirectory.kb.io,admissionReviewVersions=v1

var _ webhook.Validator = &IBMSecurityVerifyDirectory{}

/*
 * The ValidateCreate function implements a webhook.Validator so that a webhook 
 * will be registered for the type and invoked for create operations.
 */

func (r *IBMSecurityVerifyDirectory) ValidateCreate() error {
	logger.Info("validate create", "name", r.Name)

	return nil
}

/*****************************************************************************/

/*
 * The ValidateUpdate function implements a webhook.Validator so that a webhook 
 * will be registered for the type and invoked for update operations.
 */

func (r *IBMSecurityVerifyDirectory) ValidateUpdate(old runtime.Object) error {
	logger.Info("validate update", "name", r.Name)

	return nil
}

/*****************************************************************************/

/*
 * The ValidateDelete function implements a webhook.Validator so that a webhook
 * will be registered for the type and invoked for delete operations.  This
 * function is a no-op.
 */

func (r *IBMSecurityVerifyDirectory) ValidateDelete() error {
	logger.Info("validate delete", "name", r.Name)

	return nil
}

/*****************************************************************************/

