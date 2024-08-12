package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	res := `{
    "code": 0,
    "data": {
        "branchName": "master",
        "buildTime": "2024-06-11T21:28:30",
        "commitHash": "c446f6b"
    }
}`
	var apiResponse ZLMVersion
	err := json.NewDecoder(strings.NewReader(res)).Decode(&apiResponse)
	if err != nil {
		panic(err)
	}
}
