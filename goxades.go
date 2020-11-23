package xades

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	xmldsigPrefix string = ""
	Prefix        string = "xades"
	Namespace     string = "http://uri.etsi.org/01903/v1.3.2#"
)

const (
	SignedPropertiesTag          string = "SignedProperties"
	SignedSignaturePropertiesTag string = "SignedSignatureProperties"
	SigningTimeTag               string = "SigningTime"
	SigningCertificateTag        string = "SigningCertificate"
	CertTag                      string = "Cert"
	IssuerSerialTag              string = "IssuerSerial"
	CertDigestTag                string = "CertDigest"
	QualifyingPropertiesTag      string = "QualifyingProperties"
)

const (
	signedPropertiesAttr string = "SignedProperties"
	targetAttr           string = "Target"
)

var digestAlgorithmIdentifiers = map[crypto.Hash]string{
	crypto.SHA1:   "http://www.w3.org/2000/09/xmldsig#sha1",
	crypto.SHA256: "http://www.w3.org/2001/04/xmlenc#sha256",
	crypto.SHA512: "http://www.w3.org/2001/04/xmlenc#sha512",
}

var signatureMethodIdentifiers = map[crypto.Hash]string{
	crypto.SHA1:   "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
	crypto.SHA256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	crypto.SHA512: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
}

type SigningContext struct {
	DataContext       SignedDataContext
	PropertiesContext SignedPropertiesContext
	Canonicalizer     dsig.Canonicalizer
	Hash              crypto.Hash
	KeyStore          MemoryX509KeyStore
}

type SignedDataContext struct {
	Canonicalizer dsig.Canonicalizer
	Hash          crypto.Hash
	ReferenceURI  string
	IsEnveloped   bool
}

type SignedPropertiesContext struct {
	Canonicalizer dsig.Canonicalizer
	Hash          crypto.Hash
	SigninigTime  time.Time
}

//MemoryX509KeyStore struct
type MemoryX509KeyStore struct {
	PrivateKey *rsa.PrivateKey
	Cert       *x509.Certificate
	CertBinary []byte
}

//GetKeyPair func
func (ks *MemoryX509KeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.PrivateKey, ks.CertBinary, nil
}

//DigestValue calculate hash for digest
func DigestValue(element *etree.Element, canonicalizer *dsig.Canonicalizer, hash crypto.Hash) (base64encoded string, err error) {

	canonical, err := (*canonicalizer).Canonicalize(element)
	if err != nil {
		return
	}

	_hash := hash.New()
	_, err = _hash.Write(canonical)
	if err != nil {
		return "", err
	}

	base64encoded = base64.StdEncoding.EncodeToString(_hash.Sum(nil))
	return
}

//SignatureValue calculate signature
func SignatureValue(element *etree.Element, canonicalizer *dsig.Canonicalizer, hash crypto.Hash, keyStore *MemoryX509KeyStore) (base64encoded string, err error) {

	canonical, err := (*canonicalizer).Canonicalize(element)
	if err != nil {
		return
	}

	ctx := &dsig.SigningContext{
		Hash:     hash,
		KeyStore: keyStore,
	}
	buffer, err := ctx.SignString(string(canonical))
	if err != nil {
		return
	}
	base64encoded = base64.StdEncoding.EncodeToString(buffer)
	return
}

//CreateSignature create filled signature element
func CreateSignature(signedData *etree.Element, ctx *SigningContext) (*etree.Element, error) {

	//DigestValue of signedData
	digestData, err := DigestValue(signedData, &ctx.DataContext.Canonicalizer, ctx.DataContext.Hash)
	if err != nil {
		return nil, err
	}

	signingTime := ctx.PropertiesContext.SigninigTime
	if signingTime.IsZero() {
		signingTime = time.Now()
	}
	//DigestValue of signedProperties
	signedProperties := createSignedProperties(&ctx.KeyStore, signingTime)
	qualifiedSignedProperties := createQualifiedSignedProperties(signedProperties)

	digestProperties, err := DigestValue(qualifiedSignedProperties, &ctx.PropertiesContext.Canonicalizer, ctx.PropertiesContext.Hash)
	if err != nil {
		return nil, err
	}

	//SignatureValue
	signedInfo := createSignedInfo(string(digestData), string(digestProperties), ctx)
	qualifiedSignedInfo := createQualifiedSignedInfo(signedInfo)

	if err != nil {
		return nil, err
	}
	signatureValueText, err := SignatureValue(qualifiedSignedInfo, &ctx.Canonicalizer, ctx.Hash, &ctx.KeyStore)
	if err != nil {
		return nil, err
	}

	signatureValue := createSignatureValue(signatureValueText)
	keyInfo := createKeyInfo(base64.StdEncoding.EncodeToString(ctx.KeyStore.CertBinary))
	object := createObject(signedProperties)

	signature := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.SignatureTag,
		Attr: []etree.Attr{
			{Key: "Id", Value: "Signature"},
			{Key: "xmlns", Value: dsig.Namespace},
			//{Space: "xmlns", Key: xmldsigPrefix, Value: dsig.Namespace},
		},
		Child: []etree.Token{signedInfo, signatureValue, keyInfo, object},
	}
	return &signature, nil
}

func createQualifiedSignedInfo(signedInfo *etree.Element) *etree.Element {
	qualifiedSignedInfo := signedInfo.Copy()
	qualifiedSignedInfo.Attr = append(qualifiedSignedInfo.Attr, etree.Attr{Space: "xmlns", Key: xmldsigPrefix, Value: dsig.Namespace})
	return qualifiedSignedInfo
}
func createSignedInfo(digestValueDataText string, digestValuePropertiesText string, ctx *SigningContext) *etree.Element {

	var transformEnvSign etree.Element
	if ctx.DataContext.IsEnveloped {
		transformEnvSign = etree.Element{
			Space: xmldsigPrefix,
			Tag:   dsig.TransformTag,
			Attr: []etree.Attr{
				{Key: dsig.AlgorithmAttr, Value: dsig.EnvelopedSignatureAltorithmId.String()},
			},
		}
	}

	transformData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.TransformTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: ctx.DataContext.Canonicalizer.Algorithm().String()}, // "http://www.w3.org/2001/10/xml-exc-c14n#"},
		},
	}

	transformProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.TransformTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: ctx.PropertiesContext.Canonicalizer.Algorithm().String()}, // "http://www.w3.org/2001/10/xml-exc-c14n#"},
		},
	}

	transformsData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.TransformsTag,
	}
	if ctx.DataContext.IsEnveloped {
		transformsData.AddChild(&transformEnvSign)
	}
	transformsData.AddChild(&transformData)

	digestMethodData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.DigestMethodTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: digestAlgorithmIdentifiers[ctx.DataContext.Hash]},
		},
	}

	digestMethodProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.DigestMethodTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: digestAlgorithmIdentifiers[ctx.PropertiesContext.Hash]},
		},
	}

	digestValueData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.DigestValueTag,
	}
	digestValueData.SetText(digestValueDataText)

	transformsProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.TransformsTag,
		Child: []etree.Token{&transformProperties},
	}

	digestValueProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.DigestValueTag,
	}
	digestValueProperties.SetText(digestValuePropertiesText)

	canonicalizationMethod := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.CanonicalizationMethodTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: ctx.Canonicalizer.Algorithm().String()},
		},
	}

	signatureMethod := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.SignatureMethodTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: signatureMethodIdentifiers[ctx.Hash]},
		},
	}

	referenceData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.ReferenceTag,
		Attr: []etree.Attr{
			{Key: dsig.URIAttr, Value: ctx.DataContext.ReferenceURI},
		},
		Child: []etree.Token{&transformsData, &digestMethodData, &digestValueData},
	}

	referenceProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.ReferenceTag,
		Attr: []etree.Attr{
			{Key: dsig.URIAttr, Value: "#SignedProperties"},
			{Key: "Type", Value: "http://uri.etsi.org/01903#SignedProperties"},
		},
		Child: []etree.Token{&transformsProperties, &digestMethodProperties, &digestValueProperties},
	}

	signedInfo := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.SignedInfoTag,
		Child: []etree.Token{&canonicalizationMethod, &signatureMethod, &referenceData, &referenceProperties},
	}

	return &signedInfo
}

func createSignatureValue(base64Signature string) *etree.Element {
	signatureValue := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.SignatureValueTag,
	}
	signatureValue.SetText(base64Signature)
	return &signatureValue
}

func createKeyInfo(base64Certificate string) *etree.Element {

	x509Cerificate := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.X509CertificateTag,
	}
	x509Cerificate.SetText(base64Certificate)

	x509Data := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.X509DataTag,
		Child: []etree.Token{&x509Cerificate},
	}
	keyInfo := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.KeyInfoTag,
		Child: []etree.Token{&x509Data},
	}
	return &keyInfo
}

func createObject(signedProperties *etree.Element) *etree.Element {

	qualifyingProperties := etree.Element{
		Space: Prefix,
		Tag:   QualifyingPropertiesTag,
		Attr: []etree.Attr{
			{Space: "xmlns", Key: Prefix, Value: Namespace},
			{Key: targetAttr, Value: "#Signature"},
		},
		Child: []etree.Token{signedProperties},
	}
	object := etree.Element{
		Space: xmldsigPrefix,
		Tag:   "Object",
		Child: []etree.Token{&qualifyingProperties},
	}
	return &object
}

func createQualifiedSignedProperties(signedProperties *etree.Element) *etree.Element {

	qualifiedSignedProperties := signedProperties.Copy()
	qualifiedSignedProperties.Attr = append(
		signedProperties.Attr,
		etree.Attr{Space: "xmlns", Key: xmldsigPrefix, Value: dsig.Namespace},
		etree.Attr{Space: "xmlns", Key: Prefix, Value: Namespace},
	)

	return qualifiedSignedProperties
}

func createSignedProperties(keystore *MemoryX509KeyStore, signTime time.Time) *etree.Element {

	digestMethod := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.DigestMethodTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: digestAlgorithmIdentifiers[crypto.SHA1]},
		},
	}

	digestValue := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.DigestValueTag,
	}
	hash := sha1.Sum(keystore.CertBinary)
	digestValue.SetText(base64.StdEncoding.EncodeToString(hash[0:]))

	certDigest := etree.Element{
		Space: Prefix,
		Tag:   CertDigestTag,
		Child: []etree.Token{&digestMethod, &digestValue},
	}

	x509IssuerName := etree.Element{
		Space: xmldsigPrefix,
		Tag:   "X509IssuerName",
	}
	x509IssuerName.SetText(keystore.Cert.Issuer.String())
	x509SerialNumber := etree.Element{
		Space: xmldsigPrefix,
		Tag:   "X509SerialNumber",
	}
	x509SerialNumber.SetText(keystore.Cert.SerialNumber.String())

	issuerSerial := etree.Element{
		Space: Prefix,
		Tag:   IssuerSerialTag,
		Child: []etree.Token{&x509IssuerName, &x509SerialNumber},
	}

	cert := etree.Element{
		Space: Prefix,
		Tag:   CertTag,
		Child: []etree.Token{&certDigest, &issuerSerial},
	}

	signingCertificate := etree.Element{
		Space: Prefix,
		Tag:   SigningCertificateTag,
		Child: []etree.Token{&cert},
	}

	signingTime := etree.Element{
		Space: Prefix,
		Tag:   SigningTimeTag,
	}
	signingTime.SetText(signTime.Format("2006-01-02T15:04:05Z"))

	signedSignatureProperties := etree.Element{
		Space: Prefix,
		Tag:   SignedSignaturePropertiesTag,
		Child: []etree.Token{&signingTime, &signingCertificate},
	}

	signedProperties := etree.Element{
		Space: Prefix,
		Tag:   SignedPropertiesTag,
		Attr: []etree.Attr{
			{Key: "Id", Value: "SignedProperties"},
		},
		Child: []etree.Token{&signedSignatureProperties},
	}

	return &signedProperties
}
