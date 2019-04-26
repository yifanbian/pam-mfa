// +build linux darwin
package main

import "io/ioutil"
import "gopkg.in/yaml.v2"

func ReadYAML(path string) (map[string]interface{}, error) {
	yamlFile, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config map[string]interface{}
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, err
	}
	return config, nil
}
