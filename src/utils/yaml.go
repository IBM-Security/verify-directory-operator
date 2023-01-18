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

/*****************************************************************************/

/*
 * Convert the parsed YAML into a hierarchical map.
 */

func ConvertYaml(
					i interface{}) interface{} {
	switch x := i.(type) {

		case map[interface{}]interface{}:
			m2 := map[string]interface{}{}

			for k, v := range x {
				m2[k.(string)] = ConvertYaml(v)
			}

			return m2

		case []interface{}:
			for i, v := range x {
				x[i] = ConvertYaml(v)
			}

	}

    return i
}

/*****************************************************************************/

/*
 * Retrieve the value of the specified YAML.
 */

func GetYamlValue(
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
	 * We are not at the end of the key and so we need to call GetYamlValue
	 * again, moving to the next key.
	 */

	return GetYamlValue(entry, key[1:])
}

/*****************************************************************************/

