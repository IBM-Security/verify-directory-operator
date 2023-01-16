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
			h *RequestHandle) (error) {

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
		return err
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
		return err
    }

	body      = r.convertYaml(body)
	body, ok := body.(map[string]interface{})

	if ! ok {
		h.requeueOnError = false
		
		return errors.New("The server configuration cannot be parsed.")
	}

	/*
	 * Retrieve the general.ports.ldap configuration data.  
	 */

	h.config.port   = 9389
	h.config.secure = false

	ldap := r.getYamlValue(body, []string{"general","ports","ldap"})

	if ldap != nil {
		iport, ok := ldap.(int)

		if ! ok {
			h.requeueOnError = false

			return errors.New(
						"The general.ports.ldap configuration is incorrect.")
		}

		h.config.port = int32(iport)

		if h.config.port == 0 {
			/*
			 * If the port is 0 it means that it has not been activated and
			 * so we need to use the ldaps port.
			 */

			h.config.secure = true
			h.config.port   = 9636

			ldaps := r.getYamlValue(body, []string{"general","ports","ldaps"})

			if ldaps != nil {
				iport, ok := ldaps.(int)

				if ! ok {
					h.requeueOnError = false

					return errors.New(
						"The general.ports.ldaps configuration is incorrect.")
				}

				h.config.port = int32(iport)
			}
		}
	}

	/*
	 * Retrieve the license key information.
	 */

	licenseKey := r.getYamlValue(body, []string{"general","license","key"})

	if licenseKey == nil {
		h.requeueOnError = false

		return errors.New("The general.license.key configuration is missing.")
	}

	h.config.licenseKey = licenseKey.(string)

	/*
	 * Retrieve the admin DN.
	 */

	adminDn := r.getYamlValue(body, []string{"general","admin","dn"})

	if adminDn == nil {
		h.config.adminDn = "cn=root"
	} else {
		h.config.adminDn = adminDn.(string)
	}

	/*
	 * Retrieve the admin password.
	 */

	adminPwd := r.getYamlValue(body, []string{"general","admin","pwd"})

	if adminPwd == nil {
		h.requeueOnError = false

		return errors.New("The general.admin.pwd configuration is missing.")
	}

	h.config.adminPwd = adminPwd.(string)

	/*
	 * Retrieve the suffixes which are to be managed.  This is a little bit
	 * more complicated than the standard configuration entries as we need to
	 * extract each of the dn's from the suffixes entry.
	 */

	h.config.suffixes, err = r.getConfigSuffixes(body)

	if err != nil {
		h.requeueOnError = false

		return err
	}

	r.Log.Info("Server configuration information", 
				r.createLogParams(h, "port", h.config.port, 
							"is ssl", h.config.secure, 
							"license.key", h.config.licenseKey,
							"admin.dn", h.config.adminDn,
							"admin.pwd", "XXX",
							"suffixes", h.config.suffixes)...)

	return nil
}

/*****************************************************************************/

/*
 * Retrieve the suffixes which are being managed.  We need to extract each
 * of the DN values from the general.server.suffixes entry.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) getConfigSuffixes(
					body interface{}) ([]string, error) {
	var suffixes []string

	entries := r.getYamlValue(body, []string{"server","suffixes"})

	if entries == nil {
		return nil, errors.New("The server.suffixes configuration is missing.")
	}

	/*
	 * The first thing to do is cast the yaml to the correct type.
	 */

	suffixEntries, ok := entries.([]interface{}) 

	if !ok {
		return nil, errors.New(
						"The server.suffixes configuration is incorrect.")
	}

	/*
	 * Now we should iterate over the suffix entries, grabbing the DN value
	 * for each entry.
	 */

	for _, entry := range suffixEntries {
		suffixEntry, ok := entry.(map[string]interface{}) 

		if !ok {
			return nil, errors.New(
						"The server.suffixes configuration is incorrect.")
		}

		dn := r.getYamlValue(suffixEntry, []string{"dn"})

		if !ok {
			return nil, errors.New(
						"The server.suffixes configuration is incorrect.")
		}

		suffixes = append(suffixes, dn.(string))
	}

	return suffixes, nil
}

/*****************************************************************************/

