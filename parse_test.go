package main

import (
	"encoding/json"
	_ "github.com/goccy/go-yaml"
	_ "github.com/stretchr/testify/assert"
	_ "github.com/stretchr/testify/require"
	"testing"
)

func Test_unmarshalStorageAccount(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data string
		want Manifest
	}{
		{
			name: "base case",
			data: `
storageAccount:
    name: "testpipedsa"
    accountCreateParameters:
`,
			want: Manifest{
				StorageAccount: &StorageAccountTarget{
					Name:                    "testpipedsa",
					AccountCreateParameters: nil,
				},
			},
		},
	}
	//for _, tt := range tests {
	//	t.Run(tt.name, func(t *testing.T) {
	//		t.Parallel()
	//		var got Manifest
	//		var err error
	//		buf, err := yaml.YAMLToJSON([]byte(tt.data))
	//		require.NoError(t, err)
	//		err = json.Unmarshal(buf, &got)
	//		require.NoError(t, err)
	//		assert.Equal(t, tt.want, got)
	//	})
	//}
}
