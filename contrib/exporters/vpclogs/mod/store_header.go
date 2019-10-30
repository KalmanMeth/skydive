/*
 * Copyright (C) 2019 IBM, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy ofthe License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specificlanguage governing permissions and
 * limitations under the License.
 *
 */

package mod

import (
	"time"

	"github.com/spf13/viper"

	"github.com/skydive-project/skydive/logging"
)

const version = "0.0.1"

type storeHeaderVpc struct {
	keyValues map[string]string
}

// AddStoreHeader inserts the object global paramateres and wraps the flows
func (h *storeHeaderVpc) AddStoreHeader(flows []interface{}, startTime time.Time, endTime time.Time) interface{} {
	var augmentedObject map[string]interface{}
	augmentedObject = make(map[string]interface{})
	for key, value := range h.keyValues {
		augmentedObject[key] = value
	}
	augmentedObject["version"] = version
	augmentedObject["capture_start_time"] = startTime.Format(time.RFC3339)
	augmentedObject["capture_end_time"] = endTime.Format(time.RFC3339)
	augmentedObject["number_of_flow_logs"] = len(flows)
	augmentedObject["flow_logs"] = flows
	// TBD can we do better with state?
	augmentedObject["state"] = "skip data"

	return augmentedObject
}

func NewStoreHeaderVpc(cfg *viper.Viper) (interface{}, error) {
	keyValues := cfg.GetStringMapString("pipeline.storeheader.vpclogs")
	logging.GetLogger().Infof("Defined object header fields:")
	for key, value := range keyValues {
		logging.GetLogger().Infof("          %s: %s", key, value)
	}
	return &storeHeaderVpc{
		keyValues: keyValues,
	}, nil
}
