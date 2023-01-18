/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package v1

/*****************************************************************************/

import (
	corev1  "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
    "sigs.k8s.io/controller-runtime/pkg/client"

	"context"
	"errors"
	"fmt"

	"github.com/go-yaml/yaml"
	"github.com/ibm-security/verify-directory-operator/utils"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"

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

	return r.validateDocument()
}

/*****************************************************************************/

/*
 * The ValidateUpdate function implements a webhook.Validator so that a webhook 
 * will be registered for the type and invoked for update operations.
 */

func (r *IBMSecurityVerifyDirectory) ValidateUpdate(old runtime.Object) error {
	logger.Info("validate update", "name", r.Name)

	/*
	 * Validate the document itself.
	 */

	err := r.validateDocument()

	if err != nil {
		return err
	}

	/* XXX:
	 * When updating an existing document we need to:
	 *   - Ensure that the deployment is not in the failing state.  If in a
	 *     failing state we must delete the deployment first.
	 *   - Ensure that nothing within the pods entry has changed.  The only 
	 *     thing which we support editing is the number of replicas.
	 *   - Ensure that all existing pods for this deployment are currently
	 *     available and reachable.  This is achieved with the following
	 *     logic:
	 *       retrieve the list of existing pods
	 *       for each located pod:
	 *         if the pod is not available and is not being deleted:
	 *           return an error
	 *         if the pod is being deleted and has been currently set as the \
	 *         write master by the proxy:
	 *           return an error
	 */

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

func (r *IBMSecurityVerifyDirectory) validateDocument() error {
	var err error

	/*
	 * Validate that each of the PVCs specified in the document exists.
	 */

	for _, pvcName := range r.Spec.Replicas.PVCs {
		err = r.validatePVC(pvcName)

		if err != nil {
			return err
		}
	}

	if r.Spec.Pods.Proxy.PVC != "" {
		err = r.validatePVC(r.Spec.Pods.Proxy.PVC)

		if err != nil {
			return err
		}
	}

	/*
	 * Validate that each of the ConfigMaps specified in the document
	 * exists.
	 */

	maps := []IBMSecurityVerifyDirectoryConfigMapEntry {
		r.Spec.Pods.ConfigMap.Proxy,
		r.Spec.Pods.ConfigMap.Server,
	}

	for _, entry := range maps {
		err = r.validateConfigMap(entry)

		if err != nil {
			return err
		}
	}

	/*
	 * Validate the the ConfigMap's and Secrets specified within EnvFrom all
	 * exist.
	 */

	for _, envFrom := range r.Spec.Pods.EnvFrom {
		if envFrom.ConfigMapRef != nil {
			optional := envFrom.ConfigMapRef.Optional
			if optional == nil || *optional == false {
				err = r.validateConfigMap(
					IBMSecurityVerifyDirectoryConfigMapEntry {
						Name: envFrom.ConfigMapRef.LocalObjectReference.Name,
						Key:  "",
					})

				if err != nil {
					return err
				}
			}
		}

		if envFrom.SecretRef != nil {
			optional := envFrom.SecretRef.Optional
			if optional == nil || *optional == false {
				err = r.validateSecret(
								envFrom.SecretRef.LocalObjectReference.Name)

				if err != nil {
					return err
				}
			}

		}
	}

	/*
	 * Validate that the proxy ConfigMap does not contain any 
	 * serverGroups or suffixes.
	 */

	err = r.validateProxyConfigMap()

	if err != nil {
		return err
	}

	return nil
}

/*****************************************************************************/

/*
 * This function is used to validate that the specified PVC exists.
 */

func (r *IBMSecurityVerifyDirectory) validatePVC(pvcName string) (err error) {

	pvc := &corev1.PersistentVolumeClaim{}
	err  = k8s_client.Get(context.TODO(), client.ObjectKey{
							Namespace: r.Namespace,
							Name:      pvcName,
					}, pvc)

	if err != nil && k8serrors.IsNotFound(err) {
		err = errors.New(fmt.Sprintf("The PVC, %s, doesn't exist!", pvcName))
	}

	return 
}

/*****************************************************************************/

/*
 * This function is used to validate that specified ConfigMap, and optionally
 * the specified key in the ConfigMap, exists.
 */

func (r *IBMSecurityVerifyDirectory) validateConfigMap(
				entry IBMSecurityVerifyDirectoryConfigMapEntry) (err error) {

	cm := &corev1.ConfigMap{}
	err = k8s_client.Get(context.TODO(), client.ObjectKey{
							Namespace: r.Namespace,
							Name:      entry.Name,
					}, cm)

	if err != nil && k8serrors.IsNotFound(err) {
		err = errors.New(
				fmt.Sprintf("The ConfigMap, %s, doesn't exist!", entry.Name))
	}

	if err == nil && entry.Key != "" {
		_, ok := cm.Data[entry.Key]

		if ! ok {
			err = errors.New(
				fmt.Sprintf("The ConfigMap, %s, does not contain the %s key!",
						entry.Name, entry.Key))
		}
	}

	return 
}

/*****************************************************************************/

/*
 * This function is used to validate that the specified secret exists.
 */

func (r *IBMSecurityVerifyDirectory) validateSecret(
					secretName string) (err error) {

	secret := &corev1.Secret{}
	err     = k8s_client.Get(context.TODO(), client.ObjectKey{
							Namespace: r.Namespace,
							Name:      secretName,
					}, secret)

	if err != nil && k8serrors.IsNotFound(err) {
		err = errors.New(
					fmt.Sprintf("The secret, %s, doesn't exist!", secretName))
	}

	return 
}

/*****************************************************************************/

/*
 * This function is used to validate the proxy ConfigMap.  It will ensure that
 * no server groups or suffixes have been defined.
 */

func (r *IBMSecurityVerifyDirectory) validateProxyConfigMap() (err error) {

	/*
	 * Retrieve the ConfigMap which contains the proxy configuration.
	 */

	name := r.Spec.Pods.ConfigMap.Proxy.Name
	key  := r.Spec.Pods.ConfigMap.Proxy.Key

	config := &corev1.ConfigMap{}
	err	    = k8s_client.Get(context.TODO(), client.ObjectKey{
							Namespace: r.Namespace,
							Name:      name,
					}, config)

	if err != nil {
		return err
	}

	/*
	 * Parse the YAML configuration into a map.  Unfortunately it is not
	 * easy to parse YAML into a generic structure, and so after we have
	 * unmarshalled the data we want to iteratively convert the data into 
	 * a map of strings.
	 */

    var body interface{}

    if err = yaml.Unmarshal([]byte(config.Data[key]), &body); err != nil {
		return err
    }

	body = utils.ConvertYaml(body)

	/*
	 * Ensure that the server-groups and suffixes entries don't exist.
	 */

	entries := []string { "server-groups", "suffixes" }

	for _, entry := range entries {
		config := utils.GetYamlValue(body, []string{"proxy", entry})

		if config != nil {
			err = errors.New(
				fmt.Sprintf("The proxy ConfigMap key, %s:%s, includes the " +
				"proxy.%s configuration entry. This is not allowed as this " +
				"entry will be generated by the operator.", name, key, entry))

			return err
		}
	}

	return nil
}

/*****************************************************************************/

