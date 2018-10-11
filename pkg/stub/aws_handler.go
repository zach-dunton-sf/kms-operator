package stub

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/kubaj/kms-operator/pkg/apis/kubaj/v1alpha1"

	"encoding/base64"

	"github.com/sirupsen/logrus"
)

// NewAwsKMSHandler constructs AwsKMSHandler
func NewAwsKMSDecryptor(awsKMS *kms.KMS) *AwsKMSHandler {
	return &AwsKMSHandler{
		AwsKMS: awsKMS,
	}
}

type AwsKMSHandler struct {
	AwsKMS *kms.KMS
}

// Decrypt is a method that takes a secret and returns a []byte with the decrypted contents
func (h *AwsKMSHandler) Decrypt(cr *v1alpha1.SecretKMS) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(cr.Spec.Provider.Aws.Data)
	if err != nil {
		return nil, err
	}

	decryptInput := &kms.DecryptInput{
		CiphertextBlob:    b,
		EncryptionContext: nil,
		GrantTokens:       nil,
	}

	logrus.Debugln("Sending decrypt request")
	resp, err := h.AwsKMS.Decrypt(decryptInput)
	if err != nil {
		return nil, err
	}

	return resp.Plaintext, nil
}
