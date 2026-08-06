// Copyright 2025 Steffen Busch

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jwtissuer

import (
	"encoding/json"
	"net/http"
)

type apiResponse struct {
	Message string `json:"message"`
	Token   string `json:"token,omitempty"` // omitempty to not include the token field in error responses
}

// jsonResponse sends a generic JSON response with a message and optional token
func jsonResponse(w http.ResponseWriter, statusCode int, response apiResponse) error {
	w.Header().Set("Content-Type", "application/json")
	// Token-bearing responses must not be stored by browsers or intermediaries.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)
	return json.NewEncoder(w).Encode(response)
}

// jsonError simplifies sending error messages in JSON format
func jsonError(w http.ResponseWriter, statusCode int, message string) error {
	return jsonResponse(w, statusCode, apiResponse{Message: message})
}
