/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package utils

/*
 * This file contains some generic utility functions which are used by the
 * operator.
 */

/*****************************************************************************/

import (

)

/*
 * Some constants...
 */

const PVCLabel = "app.kubernetes.io/pvc-name"

/*****************************************************************************/

/*
 * Construct and return a list of labels for the deployment.
 */

func LabelsForApp(name string, pvc string) map[string]string {
	labels := map[string]string{
			"app.kubernetes.io/created-by": "verify-directory-operator",
			"app.kubernetes.io/part-of":    "verify-directory",
			"app.kubernetes.io/cr-name":    name}

	if pvc != "" {
		labels[PVCLabel] = pvc
	}

	return labels
}

/*****************************************************************************/

