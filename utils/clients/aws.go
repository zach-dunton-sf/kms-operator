package clients

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

// GetAwsKMS returns initialized Aws KMS client based on provided flags
func GetAwsKMS(enabled bool) (*kms.KMS, error) {
	if !enabled {
		return nil, nil
	}

	return kms.New(session.New()), nil
}
