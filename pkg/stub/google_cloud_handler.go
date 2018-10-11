package stub

import (
	"fmt"

	"github.com/kubaj/kms-operator/pkg/apis/kubaj/v1alpha1"
	cloudkms "google.golang.org/api/cloudkms/v1"

	"encoding/base64"

	"github.com/sirupsen/logrus"
)

// NewCloudKMSHandler constructs CloudKMSHandler
func NewCloudKMSDecryptor(cloudKMS *cloudkms.Service) *CloudKMSHandler {
	return &CloudKMSHandler{
		CloudKMS: cloudKMS,
	}
}

type CloudKMSHandler struct {
	CloudKMS *cloudkms.Service
}

// Decrypt is a method that takes a secret and returns a []byte with the decrypted contents
func (h *CloudKMSHandler) Decrypt(cr *v1alpha1.SecretKMS) ([]byte, error) {
	parent := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		cr.Spec.Provider.GoogleCloud.Project,
		cr.Spec.Provider.GoogleCloud.Location,
		cr.Spec.Provider.GoogleCloud.Keyring,
		cr.Spec.Provider.GoogleCloud.Key)

	req := &cloudkms.DecryptRequest{
		Ciphertext: cr.Spec.Provider.GoogleCloud.Data,
	}

	logrus.Debugln("Sending decrypt request")
	reqCall := h.CloudKMS.Projects.Locations.KeyRings.CryptoKeys.Decrypt(parent, req)
	resp, err := reqCall.Do()
	if err != nil {
		return nil, err
	}

	// Base64 decode after KMS call
	b, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return b, err
	}

	b, err = base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return b, err
	}

	return b, nil
}
