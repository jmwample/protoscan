package main

import (
	"encoding/hex"
	"fmt"
	"net"

	tls "github.com/refraction-networking/utls"
)

func getSpec() tls.ClientHelloSpec {
	return tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.SNIExtension{},
			&tls.UtlsExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{[]tls.CurveID{
				tls.CurveID(tls.GREASE_PLACEHOLDER),
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			}},
			&tls.SCTExtension{},
			&tls.KeyShareExtension{[]tls.KeyShare{
				{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: tls.X25519},
			}},
			&tls.PSKKeyExchangeModesExtension{[]uint8{
				tls.PskModeDHE,
			}},
			&tls.SupportedVersionsExtension{[]uint16{
				tls.GREASE_PLACEHOLDER,
				tls.VersionTLS13,
				tls.VersionTLS12,
			}},
			&tls.UtlsCompressCertExtension{},
			&tls.GenericExtension{Id: 0x4469}, // WARNING: UNKNOWN EXTENSION, USE AT YOUR OWN RISK
			&tls.UtlsGREASEExtension{},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		},
	}

}

func method3() ([]byte, error) {
	tlsConfig := tls.Config{ServerName: "tlsfingerprint.io"}
	uconn := tls.UClient(nil, &tlsConfig, tls.HelloCustom)

	clientHelloSpec := getSpec()
	uconn.ApplyPreset(&clientHelloSpec)

	err := uconn.BuildHandshakeState()
	if err != nil {
		fmt.Printf("Got error: %s; expected to succeed", err)
		return nil, err
	}

	pub := uconn.HandshakeState.Hello
	pub.Random = make([]byte, 16)
	pub.ServerName = "abcdefg.com"

	return pub.Marshal(), nil
}

func method2() ([]byte, error) {
	tlsConfig := tls.Config{ServerName: "tlsfingerprint.io"}
	uconn := tls.UClient(nil, &tlsConfig, tls.HelloCustom)

	clientHelloSpec := getSpec()
	uconn.ApplyPreset(&clientHelloSpec)

	err := uconn.BuildHandshakeState()
	if err != nil {
		fmt.Printf("Got error: %s; expected to succeed", err)
		return nil, err
	}

	raw := uconn.HandshakeState.Hello.Raw
	return raw, nil
}

func method1() ([]byte, error) {
	server, client := net.Pipe()

	tlsConfig := tls.Config{ServerName: "tlsfingerprint.io"}
	uconn := tls.UClient(client, &tlsConfig, tls.HelloCustom)

	clientHelloSpec := getSpec()
	uconn.ApplyPreset(&clientHelloSpec)
	go func() {
		uconn.Handshake()
	}()

	buf := make([]byte, 4096)
	n, err := server.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

func main() {

	for _, f := range []func() ([]byte, error){method1, method2, method3} {
		b, err := f()
		if err != nil {
			fmt.Printf("err: %v", err)
			continue
		}

		fmt.Printf("%d %s\n", len(b), hex.EncodeToString(b))
	}

}
