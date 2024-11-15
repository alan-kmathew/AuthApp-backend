const forge = require('node-forge');
const asn1 = require('asn1.js');
const { Buffer } = require('buffer');

class CSRVerifier {
    static analyzeCertificateRequest(pemCSR) {
        try {
            // Remove PEM headers and decode base64
            const csrBase64 = pemCSR
                .replace('-----BEGIN CERTIFICATE REQUEST-----', '')
                .replace('-----END CERTIFICATE REQUEST-----', '')
                .replace(/\s/g, '');
            
            const csrDer = Buffer.from(csrBase64, 'base64');
            
            // Parse the CSR using forge
            const csr = forge.pki.certificationRequestFromPem(
                '-----BEGIN CERTIFICATE REQUEST-----\n' +
                csrBase64 +
                '\n-----END CERTIFICATE REQUEST-----\n'
            );
            
            // Extract and verify information
            const analysis = {
                subject: {
                    commonName: csr.subject.getField('CN').value,
                    organization: csr.subject.getField('O').value
                },
                publicKey: {
                    algorithm: csr.publicKey.algorithm,
                    keySize: csr.publicKey.n ? csr.publicKey.n.bitLength() : 'EC key'
                },
                signature: {
                    algorithm: csr.signatureOid,
                    isValid: csr.verify(),
                    rawSignature: Buffer.from(csr.signature, 'binary').toString('base64')
                },
                attributes: csr.attributes.map(attr => ({
                    name: attr.name,
                    value: attr.value
                }))
            };
            
            return {
                isValid: true,
                analysis,
                details: {
                    totalLength: csrDer.length,
                    format: 'PKCS#10',
                    encoding: 'DER (Base64 encoded)'
                }
            };
            
        } catch (error) {
            return {
                isValid: false,
                error: error.message,
                details: {
                    errorType: 'CSR Parsing Error',
                    suggestion: 'Check if the CSR is properly formatted'
                }
            };
        }
    }
}

// Example CSR for verification
const csr = `-----BEGIN CERTIFICATE REQUEST-----
MH4wMjERMA8GA1UEAwwISm9obiBEb2UxHTAbBgNVBAoMFEV4YW1wbGUgT3JnYW5pemF0aW9uA0gAMEUCIQCQxGZING2RPen8u9XpN3X90x7QiuvVYrssCkP9/Ih6ywIgSAsC34LbxJYKSdPThGfrKQa2lLnKiFa1iwrZEQIO5QE=
-----END CERTIFICATE REQUEST-----`;

// Analyze the CSR
const result = CSRVerifier.analyzeCertificateRequest(csr);
console.log('CSR Analysis Result:');
console.log(JSON.stringify(result, null, 2));

// Additional helper function to extract the public key
function extractPublicKey(csrPem) {
    const csr = forge.pki.certificationRequestFromPem(csrPem);
    const publicKeyPem = forge.pki.publicKeyToPem(csr.publicKey);
    return publicKeyPem;
}