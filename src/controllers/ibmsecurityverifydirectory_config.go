/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package controllers

/*
 * This file contains the functions which are used by the controller to manage
 * access to the server configuration.
 */

/*****************************************************************************/

import (
	corev1  "k8s.io/api/core/v1"

	"errors"

	"k8s.io/apimachinery/pkg/types"

	"github.com/go-yaml/yaml"
)

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
 * The following function is used to retrieve the server configuration which 
 * is to be used by the pods.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) getServerConfig(
			h *RequestHandle) (int32, bool, string, error) {

	/*
	 * Retrieve the ConfigMap which contains the server configuration.
	 */

	name := h.directory.Spec.Pods.ConfigMap.Server.Name
	key  := h.directory.Spec.Pods.ConfigMap.Server.Key

	config := &corev1.ConfigMap{}
	err	   := r.Get(h.ctx, 
			types.NamespacedName{Name: name, Namespace: h.directory.Namespace}, 
			config)

	if err != nil {
		return 0, false, "", err
	}

	/*
	 * Parse the YAML configuration into a map.  Unfortunately it is not
	 * easy to parse YAML into a generic structure, and so after we have
	 * unmarshalled the data we want to iteratively convert the data into 
	 * a map of strings.
	 */

    var body interface{}
    if err := yaml.Unmarshal([]byte(config.Data[key]), &body); err != nil {
		h.requeueOnError = false
		return 0, false, "", err
    }

	body      = r.convertYaml(body)
	body, ok := body.(map[string]interface{})

	if ! ok {
		h.requeueOnError = false
		
		return 0, false, "", errors.New(
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
			h.requeueOnError = false

			return 0, false, "", errors.New(
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
					h.requeueOnError = false

					return 0, false, "", errors.New(
						"The general.ports.ldaps configuration is incorrect.")
				}

				port = int32(iport)
			}
		}
	}

	/*
	 * Retrieve the license key information.
	 */

	license := r.getYamlValue(body, []string{"general","license","key"})

	if license == nil {
		h.requeueOnError = false

		return 0, false, "", errors.New(
						"The general.license.key configuration is missing.")
	}


	r.Log.Info("Server configuration information", 
				r.createLogParams(h, "port", port, "is ssl", secure, 
							"license.key", license)...)

	return port, secure, license.(string), nil
}

/*****************************************************************************/

