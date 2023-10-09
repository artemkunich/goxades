package xades

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

const testKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA1+mO1JuSbRsqc4Z90qS8R6I9+OjYTgEr8fgcVOSfMSTmfKkn
ov+tWgl9ZK4GsfSvjc89OURbAx6131nbyiNMm91qqVnCMN4HWGKBm1vDuKQCDEd6
zqv+uVB9cAD9GKyVqnurmdWFgA3uFEA+xUbWLwY6fLhVNAKTgFZpZdVMCigiAK9t
wXJsCus72wWMch5pFvScIDmSeE/saRzdjLEDROwikuFYxLJxcLDDtwrBUQxRK0UW
xTqGLKSik5rKqp4A5D6kAgNDp9yEeunw9JtwXsGnrJFav0fUlREQVAU6SdftbOds
GqJogNheGZp2yFSwBkxPoj/z277E/M5+w4hUmwIDAQABAoIBAQCz4+Ff3FqMUwT0
icqNVTmViWSO3RlTLIC7speQV4cXAAKVPK5MjS+Wg6+Y0bG8VPxrb444B264075+
X7TS3sQ2XK1AegtkgainCDOqCDOyw9r89hUo2n55UcmhJwG4rBpql21q107KWVDS
SJDD9vf+5/aU8VPz6G2SkOxxrtwS3MNqGLIpo2cO1sXfGHDwZR96TbXQhUFRntE3
gXfH/aZtBjI/7/PLgL/WUmaa93YNqK8fQMCu5ig+NS4DAKpAVVlb2XXuxDHd5e0c
GS6h1lQTi2pycNbRphkAcSf0s3FxVclHsMA4jxT0KEeO80OsHQ9wyMz1LaSUepBO
n+gu7Z55AoGBAOyPac8shiRSsCQvocaKl/dawec4BD8W4zJTAN7+6qT/whTR4mIH
5XThUNMMcJyZnNkuAF0i3AASfSA964QFbnjTJVToEDGWsgbzFOnaAILiVEKvk4PZ
mZRZjuEPej/hFJWoTb7VlpUxh4NVkSAM8nrJrq/Dq2YsSLuLvZRkB8UXAoGBAOmn
xO08u1SDXFWgjHkIzGGs6IpfeJ5uzzZAiTpM6xvzJIjB/l6hSWaUBkecX1/YjjAj
3SUX/gNBx1I2Vb7NzsdZhqJCGtzVrQ6lO00uYFUmzQ5ukjKSVen5FS2CoRtPBdI/
9gPZRKQ/JjEKVvTxyyoOQrCTA8XDOzjZiVGis6cdAoGBANRDo1foxb0WDUOLEgiL
F+02HMOSugy6RsdDP4bZCkdfzxDLe+0m1LfZ7aJSiUGbfOhLpLvtqabO8EPcC9Z8
4TG9lMPpL46vf7NIrz1fBhJrb9wem6k1ud8ptVExiCqFlujrCkfwc5wPw18PipdN
xs5y5jKEyul1VxYiP8xFLculAoGANBlRgqh5CLYln34l9FLu55SbYUc6aPFCSNGJ
B7Pg9KF5cvj2k/kYmcPFxq/qYD+0LK3CgKPh4q4HGKC+68WOJssihwmAXd9TMCHN
oD8IAdSeAmrLNHWGrJ36h+RJsgIjxSa331HRyWG/TU4F56YGbAE0A5U0USNgECQJ
R2ek8U0CgYEAwzHEZCe4vLQRItgcI0lZMPlZwS4ojHH2X8tj+DYgyzk+hay0EPuS
1VILuV2jrNxLP4s2xMIofy+LsVWxBnSIj1pVHhuIjtNlM11NnjyNkyIrZsfgRjcl
gXTRx5TPgdRJ1UL8zE3+VX+aTVd33KA3gMu7ug+oRC2PiVSoMv3Ftdo=
-----END RSA PRIVATE KEY-----`

const testCert = `-----BEGIN CERTIFICATE-----
MIIDfTCCAmWgAwIBAgIISkfY2MkXC5MwDQYJKoZIhvcNAQELBQAwXDELMAkGA1UE
BhMCQ1oxDzANBgNVBAgTBlByYWd1ZTEhMB8GA1UEChMYVGVzdCBvcmdhbml6YXRp
b24gcyByLm8uMRkwFwYDVQQDExBUZXN0IGNlcnRpZmljYXRlMCAXDTIwMTEyMTEz
MDgwMFoYDzMwMjAxMTIxMTMwODAwWjBcMQswCQYDVQQGEwJDWjEPMA0GA1UECBMG
UHJhZ3VlMSEwHwYDVQQKExhUZXN0IG9yZ2FuaXphdGlvbiBzIHIuby4xGTAXBgNV
BAMTEFRlc3QgY2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDX6Y7Um5JtGypzhn3SpLxHoj346NhOASvx+BxU5J8xJOZ8qSei/61aCX1k
rgax9K+Nzz05RFsDHrXfWdvKI0yb3WqpWcIw3gdYYoGbW8O4pAIMR3rOq/65UH1w
AP0YrJWqe6uZ1YWADe4UQD7FRtYvBjp8uFU0ApOAVmll1UwKKCIAr23BcmwK6zvb
BYxyHmkW9JwgOZJ4T+xpHN2MsQNE7CKS4VjEsnFwsMO3CsFRDFErRRbFOoYspKKT
msqqngDkPqQCA0On3IR66fD0m3BewaeskVq/R9SVERBUBTpJ1+1s52waomiA2F4Z
mnbIVLAGTE+iP/PbvsT8zn7DiFSbAgMBAAGjQTA/MAsGA1UdDwQEAwIHgDAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEQYJYIZIAYb4QgEBBAQDAgbAMA0G
CSqGSIb3DQEBCwUAA4IBAQDOOo//TnNQm1yvZZ7cmx2R87WVx/4DBpoJOp+MLdDt
l3o2Hc4ma1wAGsmaE8Kt+7SNmMACrjnaVuYtVpTqY8wW2/17vPyIajjlLRe9EINO
VkZ8ux3Iq8BUn/ARDkC5Wj6QUxWWesRXc2yt9XAixqxKocFVlkb0o7oXNkEzPW+G
DH2TSEmOaLR4TEwuA559+xpfsGCdDNsXcQpjvsqOpbwpEy5ulNL/SZ1bVqzYAohC
mQtNl5eQmOt4DqkEKIuE4yzycOJPgA10UIh5WM1xgTo6rDfhytcExkxzcHS5MBBj
WKEu2X4BA5kpShcypoinxIuLBdjsuGoo41mJZMxAh0Ay
-----END CERTIFICATE-----
`

const testXML = `<informCreditor id="signedData" xmlns="urn:czech-ba:instant-payments:v1:instantPayment"><xid>X9999000000000001</xid><transactionStatus><statusCode>IN_DELIVERY</statusCode></transactionStatus><CdtTrfTxInf xmlns="urn:czech-ba:instant-payments:v1:derivedpacs.008.001.02"><PmtId><TxId>20200101 0000000001</TxId></PmtId><InstdAmt Ccy="CZK">1.01</InstdAmt><Dbtr><Nm>Koláček Tvarohový</Nm></Dbtr><DbtrAcct><Id><IBAN>CZ7130300000001000043013</IBAN></Id></DbtrAcct><CdtrAcct><Id><IBAN>CZ1360000000000000000019</IBAN></Id></CdtrAcct><RmtInf><Ustrd>TentoTextZprávyProPříjemceJeVyplněnNaMaximálníMožnouDélkuSloužíKpřípadnéIdentifikaciChybVTestováníZároveňJeKontrolovánaDiakritikaVýpisů</Ustrd><Strd><CdtrRefInf><Ref>VS:7777777777</Ref></CdtrRefInf></Strd><Strd><CdtrRefInf><Ref>KS:0308</Ref></CdtrRefInf></Strd><Strd><CdtrRefInf><Ref>SS:2222222222</Ref></CdtrRefInf></Strd></RmtInf></CdtTrfTxInf><timestamps><T2>2020-01-01T00:00:00+01:00</T2><TR>2020-01-01T00:00:00+01:00</TR></timestamps></informCreditor>`

var (
	testKeyStore *MemoryX509KeyStore
)

func getTestKeyStore() (*MemoryX509KeyStore, error) {

	if testKeyStore != nil {
		return testKeyStore, nil
	}

	blockc, _ := pem.Decode([]byte(testCert))
	cert, err := x509.ParseCertificate(blockc.Bytes)
	if err != nil {
		return nil, err
	}
	blockp, _ := pem.Decode([]byte(testKey))
	key, err := x509.ParsePKCS1PrivateKey(blockp.Bytes)
	if err != nil {
		return nil, err
	}

	testKeyStore = &MemoryX509KeyStore{
		PrivateKey: key,
		Cert:       cert,
		CertBinary: blockc.Bytes,
	}
	return testKeyStore, nil
}

func getSigningContextMap(t *testing.T) (ctxMap map[*SigningContext]string) {

	ctxMap = make(map[*SigningContext]string)

	keyStore, err := getTestKeyStore()
	require.NoError(t, err)

	signingTime, err := time.Parse("2006-01-02T15:04:05Z", "2020-01-01T00:00:00Z")
	require.NoError(t, err)

	c14N10ExclusiveCanonicalizer := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	ctx := &SigningContext{
		DataContext: SignedDataContext{
			Canonicalizer: c14N10ExclusiveCanonicalizer,
			Hash:          crypto.SHA256,
			IsEnveloped:   true,
			ReferenceURI:  "#signedData",
		},
		PropertiesContext: SignedPropertiesContext{
			Canonicalizer: c14N10ExclusiveCanonicalizer,
			Hash:          crypto.SHA256,
			SigninigTime:  signingTime,
		},
		Canonicalizer: c14N10ExclusiveCanonicalizer,
		Hash:          crypto.SHA256,
		KeyStore:      *keyStore,
	}
	ctxMap[ctx] = "qCBQF0f51nnIa44jR89dgE2KBhnrkq41i0YFYtpIDXQFpzoFubuWLuHbEeP1V8KTImkWkSWzsg2h8sdVaZ7r7E6ABZKyCC4u12aHI/Tzq0yuNP9/VkdIzkKOLRbzPfjQVSZWGjkpOnwA5Q2HsN579oqQovrTikJ+W5At9ux79SOLNmZJFZp5QMC2Hn1fWoBWdXnuwAFLLqhspVpPRZq9qXeVcxwtbWN+Z9KYEt96NLWCgHYAxqrNauN4IJ+dpYPOo3w1NHucsb78PvWCGHlfmBYOgAzGkfqTJ/fqfbBTxeYBWBJKVYvJjlMivLh3Ss/dHSJEvU6pRFLUFXf9D9KHnQ=="

	ctx = &SigningContext{
		DataContext: SignedDataContext{
			Canonicalizer: c14N10ExclusiveCanonicalizer,
			Hash:          crypto.SHA1,
			ReferenceURI:  "#signedData",
		},
		PropertiesContext: SignedPropertiesContext{
			Canonicalizer: c14N10ExclusiveCanonicalizer,
			Hash:          crypto.SHA1,
			SigninigTime:  signingTime,
		},
		Canonicalizer: c14N10ExclusiveCanonicalizer,
		Hash:          crypto.SHA256,
		KeyStore:      *keyStore,
	}
	ctxMap[ctx] = "0NjE/1BhL8vRz3bKujsFFkuyPvnANBVdWWShf7RIhrElJOg9TtuK6QGPrADx8B5zjCPOA74Gi7HdMmlQa5SNyAny+qGElMquw9i2ou4VSZkhaho1Xz9Hn5DprqKBnCLL0fS7JV+5TgmfoMz0R2oEWwFzoa7fz4rFu84AGKq4tidwk8Qq5hJ6XsVnLiaQq1h4etKGBh2wSopMFemI5k8dbS/VK/M+Ue7N01QgnC5FzRrzEw/5+ZTQndnUfpa11LzGJuretHuQYVrDLzbuqtOmNVyEjyziACB3yr8D2MFYaLZutQ9JBa44EuVjQj7w9qBLFk1ceBee/TDxc5hb5Zo+8Q=="

	return
}

func getSigningContextNamespacePrefixMap(t *testing.T) (ctxMap map[*SigningContext]string) {

	ctxMap = make(map[*SigningContext]string)

	keyStore, err := getTestKeyStore()
	require.NoError(t, err)

	signingTime, err := time.Parse("2006-01-02T15:04:05Z", "2020-01-01T00:00:00Z")
	require.NoError(t, err)

	c14N10ExclusiveCanonicalizer := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	ctx := &SigningContext{
		DataContext: SignedDataContext{
			Canonicalizer: c14N10ExclusiveCanonicalizer,
			Hash:          crypto.SHA256,
			IsEnveloped:   true,
			ReferenceURI:  "#signedData",
		},
		PropertiesContext: SignedPropertiesContext{
			Canonicalizer: c14N10ExclusiveCanonicalizer,
			Hash:          crypto.SHA256,
			SigninigTime:  signingTime,
		},
		Canonicalizer: c14N10ExclusiveCanonicalizer,
		Hash:          crypto.SHA256,
		KeyStore:      *keyStore,
		XmlDsigPrefix: "ds",
	}
	ctxMap[ctx] = "lFQkrk5ZfFxGoIkUR2XMWwFbGhv4n6oLw+/KIUM+JcEnVM8ebr47d7lpM2vviBa5zCR/IgK3nB/CIjPcgA0v5KILKp0K9M7PNL5IikxDVu7l1PVcAUaQG7NhMrwNTiY6g5EhLCIkv04q1jTXWCaCyYdRf1IMpgc1LN6v2CfRIl3xfOqUY/cBsp8jRP8LTtU5H7OeNjVmRjrCyUmKgfTnNJOG0oxhadzqs4/MIJgMoz5090k4NXFRM+JW/g/adXMa45kNcLhkyXEH/co/wRN4UsR9Se/X+gh1bFDhOiqyyzveOKCxWACJR8+vF1ao5LWy+kWGkzUCEg81ouqxqWYgOw=="

	ctx = &SigningContext{
		DataContext: SignedDataContext{
			Canonicalizer: c14N10ExclusiveCanonicalizer,
			Hash:          crypto.SHA1,
			ReferenceURI:  "#signedData",
		},
		PropertiesContext: SignedPropertiesContext{
			Canonicalizer: c14N10ExclusiveCanonicalizer,
			Hash:          crypto.SHA1,
			SigninigTime:  signingTime,
		},
		Canonicalizer: c14N10ExclusiveCanonicalizer,
		Hash:          crypto.SHA256,
		KeyStore:      *keyStore,
		XmlDsigPrefix: "ds",
	}
	ctxMap[ctx] = "tGaU8GC1mfQgHlJJUznKLIvUEGZqfjp7VyatB71ctAlUMrdqDlzbYAGoFQE5jru+z/OxBvKFiSK9cYP85Y2YXajm6cdnNumtA7nfrBhQoldeoKQZZvqVoPBsL48YzDpBLutnRrqcBzsYiUs8PGpLaciwIKFaHIFEl6H7Z4W4wGsdAn99IFOmeAdo403z6AerYrZgZQeEpiI86Z5OIHbem6lqxf/DPW4BNWYbREVH7srPsU1jGPhZKDInUJJ4iBiuGXWV9O15FE97VDjleQQtB8rC30dZFcFQyv9ML6NPIntwBw+KqXmb8ThKyi3qqD3qIaKDTCecoaJXktvWiRvYMw=="

	return
}

func TestSignature(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(testXML)
	require.NoError(t, err)

	signedData := doc.Root()

	ctxMap := getSigningContextMap(t)

	for ctx, signatureValue := range ctxMap {
		testSignature(t, signedData, ctx)
		testSignatureValue(t, signedData, ctx, signatureValue)
	}
}

func TestNamespacePrefixSignature(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(testXML)
	require.NoError(t, err)

	signedData := doc.Root()

	ctxMap := getSigningContextNamespacePrefixMap(t)

	for ctx, signatureValue := range ctxMap {
		testSignature(t, signedData, ctx)
		testSignatureValue(t, signedData, ctx, signatureValue)
	}
}

func testSignature(t *testing.T, signedData *etree.Element, ctx *SigningContext) {
	xmldsigPrefix := ctx.XmlDsigPrefix
	signature, err := CreateSignature(signedData, ctx)
	require.NoError(t, err)

	signedInfo := signature.FindElement(xmldsigPrefix + ":" + dsig.SignedInfoTag)
	require.NotEmpty(t, signedInfo)
	testSignedInfo(t, signedInfo, ctx)

	signatureValue := signature.FindElement(xmldsigPrefix + ":" + dsig.SignatureValueTag)
	require.NotEmpty(t, signatureValue)

	keyInfo := signature.FindElement(xmldsigPrefix + ":" + dsig.KeyInfoTag)
	require.NotEmpty(t, keyInfo)
	testKeyInfo(t, keyInfo, ctx)

	object := signature.FindElement(xmldsigPrefix + ":" + "Object")
	require.NotEmpty(t, object)
	testObject(t, object, ctx)
}

func testSignedInfo(t *testing.T, signedInfo *etree.Element, ctx *SigningContext) {
	xmldsigPrefix := ctx.XmlDsigPrefix
	canonicalizationMethodElement := signedInfo.FindElement(xmldsigPrefix + ":" + dsig.CanonicalizationMethodTag)
	require.NotEmpty(t, canonicalizationMethodElement)

	canonicalizationMethodAttr := canonicalizationMethodElement.SelectAttr(":" + dsig.AlgorithmAttr)
	require.NotEmpty(t, canonicalizationMethodAttr)
	require.Equal(t, ctx.Canonicalizer.Algorithm().String(), canonicalizationMethodAttr.Value)

	signatureMethodElement := signedInfo.FindElement(xmldsigPrefix + ":" + dsig.SignatureMethodTag)
	require.NotEmpty(t, signatureMethodElement)

	signatureMethodAttr := signatureMethodElement.SelectAttr(":" + dsig.AlgorithmAttr)
	require.NotEmpty(t, signatureMethodAttr)
	require.Equal(t, signatureMethodIdentifiers[ctx.Hash], signatureMethodAttr.Value)

	referenceElements := signedInfo.FindElements(xmldsigPrefix + ":" + dsig.ReferenceTag)
	require.NotEmpty(t, referenceElements)
	require.Len(t, referenceElements, 2)
	testReferenceData(t, referenceElements[0], &ctx.DataContext, ctx.XmlDsigPrefix)
	testReferenceProperties(t, referenceElements[1], &ctx.PropertiesContext, ctx.XmlDsigPrefix)

}

func testReferenceData(t *testing.T, referenceElement *etree.Element, ctx *SignedDataContext, xmldsigPrefix string) {
	idAttr := referenceElement.SelectAttr(":" + dsig.URIAttr)
	require.NotEmpty(t, idAttr)
	require.Equal(t, ctx.ReferenceURI, idAttr.Value)

	transformsElement := referenceElement.FindElement(xmldsigPrefix + ":" + dsig.TransformsTag)
	require.NotEmpty(t, transformsElement)

	transformElements := transformsElement.FindElements(xmldsigPrefix + ":" + dsig.TransformTag)
	require.NotEmpty(t, transformElements)

	var algorithmAttr *etree.Attr
	if ctx.IsEnveloped {
		require.Len(t, transformElements, 2)
		algorithmAttr = transformElements[0].SelectAttr(":" + dsig.AlgorithmAttr)
		require.NotEmpty(t, algorithmAttr)
		require.Equal(t, dsig.EnvelopedSignatureAltorithmId.String(), algorithmAttr.Value)
		algorithmAttr = transformElements[1].SelectAttr(":" + dsig.AlgorithmAttr)
	} else {
		require.Len(t, transformElements, 1)
		algorithmAttr = transformElements[0].SelectAttr(":" + dsig.AlgorithmAttr)
	}

	require.NotEmpty(t, algorithmAttr)
	require.Equal(t, ctx.Canonicalizer.Algorithm().String(), algorithmAttr.Value)

	digestMethod := referenceElement.FindElement(xmldsigPrefix + ":" + dsig.DigestMethodTag)
	require.NotEmpty(t, digestMethod)
	algorithmAttr = digestMethod.SelectAttr(":" + dsig.AlgorithmAttr)
	require.NotEmpty(t, algorithmAttr)
	require.Equal(t, digestAlgorithmIdentifiers[ctx.Hash], algorithmAttr.Value)

	digestValue := referenceElement.FindElement(xmldsigPrefix + ":" + dsig.DigestValueTag)
	require.NotEmpty(t, digestValue)
}

func testReferenceProperties(t *testing.T, referenceElement *etree.Element, ctx *SignedPropertiesContext, xmldsigPrefix string) {
	idAttr := referenceElement.SelectAttr(":" + dsig.URIAttr)
	require.NotEmpty(t, idAttr)
	require.Equal(t, "#SignedProperties", idAttr.Value)

	transformsElement := referenceElement.FindElement(xmldsigPrefix + ":" + dsig.TransformsTag)
	require.NotEmpty(t, transformsElement)

	transformElements := transformsElement.FindElements(xmldsigPrefix + ":" + dsig.TransformTag)
	require.NotEmpty(t, transformElements)
	require.Len(t, transformElements, 1)

	algorithmAttr := transformElements[0].SelectAttr(":" + dsig.AlgorithmAttr)
	require.NotEmpty(t, algorithmAttr)
	require.Equal(t, ctx.Canonicalizer.Algorithm().String(), algorithmAttr.Value)

	digestMethod := referenceElement.FindElement(xmldsigPrefix + ":" + dsig.DigestMethodTag)
	require.NotEmpty(t, digestMethod)
	algorithmAttr = digestMethod.SelectAttr(":" + dsig.AlgorithmAttr)
	require.NotEmpty(t, algorithmAttr)
	require.Equal(t, digestAlgorithmIdentifiers[ctx.Hash], algorithmAttr.Value)

	digestValue := referenceElement.FindElement(xmldsigPrefix + ":" + dsig.DigestValueTag)
	require.NotEmpty(t, digestValue)
}

func testKeyInfo(t *testing.T, keyInfo *etree.Element, ctx *SigningContext) {
	xmldsigPrefix := ctx.XmlDsigPrefix
	x509Data := keyInfo.FindElement(xmldsigPrefix + ":" + dsig.X509DataTag)
	require.NotEmpty(t, x509Data)

	x509Certificate := x509Data.FindElement(xmldsigPrefix + ":" + dsig.X509CertificateTag)
	require.NotEmpty(t, x509Certificate)
	require.Equal(t, base64.StdEncoding.EncodeToString(ctx.KeyStore.CertBinary), x509Certificate.Text())
}

func testObject(t *testing.T, keyInfo *etree.Element, ctx *SigningContext) {
	xmldsigPrefix := ctx.XmlDsigPrefix
	qualifyingProperties := keyInfo.FindElement(Prefix + ":" + QualifyingPropertiesTag)
	require.NotEmpty(t, qualifyingProperties)
	//require.Equal(t, Prefix, qualifyingProperties.Space)

	xmlnsAttr := qualifyingProperties.SelectAttr("xmlns" + ":" + Prefix)
	require.NotEmpty(t, xmlnsAttr)
	require.Equal(t, Namespace, xmlnsAttr.Value)

	targetAttr := qualifyingProperties.SelectAttr(":" + targetAttr)
	require.NotEmpty(t, targetAttr)
	require.Equal(t, "#Signature", targetAttr.Value)

	signedProperties := qualifyingProperties.FindElement(Prefix + ":" + SignedPropertiesTag)
	require.NotEmpty(t, signedProperties)

	idAttr := signedProperties.SelectAttr(":" + "Id")
	require.NotEmpty(t, idAttr)
	require.Equal(t, "SignedProperties", idAttr.Value)

	signedSignatureProperties := signedProperties.FindElement(Prefix + ":" + SignedSignaturePropertiesTag)
	require.NotEmpty(t, signedSignatureProperties)

	signingTime := signedSignatureProperties.FindElement(Prefix + ":" + SigningTimeTag)
	require.NotEmpty(t, signingTime)

	signTime, err := time.Parse("2006-01-02T15:04:05Z", signingTime.Text())
	require.NoError(t, err)
	if !ctx.PropertiesContext.SigninigTime.IsZero() {
		require.Equal(t, ctx.PropertiesContext.SigninigTime.Format("2006-01-02T15:04:05Z"), signTime.Format("2006-01-02T15:04:05Z"))
	}

	signingCertificate := signedSignatureProperties.FindElement(Prefix + ":" + SigningCertificateTag)
	require.NotEmpty(t, signingCertificate)

	cert := signingCertificate.FindElement(Prefix + ":" + CertTag)
	require.NotEmpty(t, cert)

	certDigest := cert.FindElement(Prefix + ":" + CertDigestTag)
	require.NotEmpty(t, certDigest)

	digestMethod := certDigest.FindElement(xmldsigPrefix + ":" + dsig.DigestMethodTag)
	require.NotEmpty(t, digestMethod)
	algorithmAttr := digestMethod.SelectAttr(":" + dsig.AlgorithmAttr)
	require.NotEmpty(t, algorithmAttr)
	require.Equal(t, digestAlgorithmIdentifiers[crypto.SHA1], algorithmAttr.Value)

	digestValue := certDigest.FindElement(xmldsigPrefix + ":" + dsig.DigestValueTag)
	require.NotEmpty(t, digestValue)
	hash := sha1.Sum(ctx.KeyStore.CertBinary)
	require.Equal(t, base64.StdEncoding.EncodeToString(hash[0:]), digestValue.Text())

	issuerSerial := cert.FindElement(Prefix + ":" + IssuerSerialTag)
	require.NotEmpty(t, issuerSerial)

	x509IssuerName := issuerSerial.FindElement(xmldsigPrefix + ":" + "X509IssuerName")
	require.NotEmpty(t, x509IssuerName)
	require.Equal(t, ctx.KeyStore.Cert.Issuer.String(), x509IssuerName.Text())

	x509SerialNumber := issuerSerial.FindElement(xmldsigPrefix + ":" + "X509SerialNumber")
	require.NotEmpty(t, x509SerialNumber)
	require.Equal(t, ctx.KeyStore.Cert.SerialNumber.String(), x509SerialNumber.Text())
}

func testSignatureValue(t *testing.T, signedData *etree.Element, ctx *SigningContext, expectedValue string) {
	xmldsigPrefix := ctx.XmlDsigPrefix
	signature, err := CreateSignature(signedData, ctx)
	require.NoError(t, err)

	signatureValue := signature.FindElement(xmldsigPrefix + ":" + dsig.SignatureValueTag)
	require.NotEmpty(t, signatureValue)
	require.Equal(t, expectedValue, signatureValue.Text())
}
