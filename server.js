const express = require('express');
const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

// Generate a self-signed CA certificate if it doesn't exist
const caKeyPath = path.join(__dirname, 'ca_key.pem');
const caCertPath = path.join(__dirname, 'ca_cert.pem');

let caPrivateKey, caCertificate;

if (!fs.existsSync(caKeyPath) || !fs.existsSync(caCertPath)) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  caPrivateKey = keys.privateKey;
  
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
  
  const attrs = [{
    name: 'commonName',
    value: 'Mock CA'
  }, {
    name: 'countryName',
    value: 'Germany'
  }, {
    shortName: 'ST',
    value: 'Mannheim'
  }, {
    name: 'localityName',
    value: 'Mannheim'
  }, {
    name: 'organizationName',
    value: 'Mock PKI'
  }, {
    shortName: 'OU',
    value: 'Mock PKI'
  }];
  
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([{
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }, {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true
  }]);
  
  cert.sign(caPrivateKey, forge.md.sha256.create());
  
  caCertificate = cert;
  
  fs.writeFileSync(caKeyPath, forge.pki.privateKeyToPem(caPrivateKey));
  fs.writeFileSync(caCertPath, forge.pki.certificateToPem(caCertificate));
} else {
  const caKeyPem = fs.readFileSync(caKeyPath, 'utf8');
  const caCertPem = fs.readFileSync(caCertPath, 'utf8');
  caPrivateKey = forge.pki.privateKeyFromPem(caKeyPem);
  caCertificate = forge.pki.certificateFromPem(caCertPem);
}

//   try {
//     const { csr } = req.body;
//     console.log('Received CSR:', csr);

//     if (!csr) {
//       return res.status(400).json({ error: 'CSR is required' });
//     }

//     const csrObj = forge.pki.certificationRequaestFromPem(csr);
    
//     // Log CSR details
//     console.log('CSR Subject:', csrObj.subject.attributes);
//     console.log('CSR Public Key:', csrObj.publicKey);
//     console.log('CSR Signature:', csrObj.signature);

//     // Verify the CSR
//     if (!csrObj.verify()) {
//       return res.status(400).json({ error: 'Invalid CSR' });
//     }
    
//     const serviceCardId = "SC123456";
//     const userRole = "technician";
//     const info = JSON.stringify({
//       serviceCardId,
//       userRole,
//       timestamp: new Date().toISOString()
//     });

//     const blobData = Buffer.from(info).toString('base64');

//     const cert = forge.pki.createCertificate();
//     cert.publicKey = csrObj.publicKey;
//     cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
//     cert.validity.notBefore = new Date();
//     cert.validity.notAfter = new Date();
//     cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    
//     cert.setSubject(csrObj.subject.attributes);
//     cert.setIssuer(caCertificate.subject.attributes);

//     // Generate authorityKeyIdentifier
//     const authorityKeyId = forge.pki.getPublicKeyFingerprint(caCertificate.publicKey, { encoding: 'hex' });
//     const authorityKeyIdentifier = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
//       forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, 
//         forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, 
//           forge.util.hexToBytes(authorityKeyId)
//         )
//       )
//     ]);

//     // User notice and certificate policies
//     const policies = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
//       forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, 
//         forge.asn1.oidToDer('1.3.6.1.5.5.7.2.2').getBytes()
//       ),
//       forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
//         forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.UTF8, false, "Data : " + blobData)      ])
//     ]);

//     cert.setExtensions([
//       { name: 'basicConstraints', cA: false },
//       { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, dataEncipherment: true },
//       { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
//       { id: '2.5.29.35', critical: false, value: authorityKeyIdentifier },
//       { name: 'subjectKeyIdentifier' }, // Automatically generated
//       { id: '2.5.29.32', critical: false, value: policies }
//     ]);
    
//     cert.sign(caPrivateKey, forge.md.sha256.create());
    
//     const certPem = forge.pki.certificateToPem(cert);
    
//     res.json({ certificate: certPem });
//   } catch (error) {
//     console.error('Error signing CSR:', error);
//     res.status(500).json({ error: 'Internal server error' });
//   }
// });

// In your server.js, modify the /sign-csr endpoint to:
app.post('/sign-csr', (req, res) => {
  try {
    const { publicKey, subject } = req.body;
    console.log('Received public key and subject:', { subject });

    if (!publicKey) {
      return res.status(400).json({ error: 'Public key is required' });
    }

    // Convert PEM public key to forge public key
    const publicKeyObj = forge.pki.publicKeyFromPem(publicKey);
    
    const serviceCardId = "SC123456";
    const userRole = "technician";
    const info = JSON.stringify({
      serviceCardId,
      userRole,
      timestamp: new Date().toISOString()
    });

    const blobData = Buffer.from(info).toString('base64');

    // Create certificate directly
    const cert = forge.pki.createCertificate();
    cert.publicKey = publicKeyObj;
    cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    
    // Set subject from the request
    const subjectAttrs = Object.entries(subject).map(([key, value]) => ({
      name: key,
      value: value
    }));
    
    cert.setSubject(subjectAttrs);
    cert.setIssuer(caCertificate.subject.attributes);

    // Generate authorityKeyIdentifier
    const authorityKeyId = forge.pki.getPublicKeyFingerprint(caCertificate.publicKey, { encoding: 'hex' });
    const authorityKeyIdentifier = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, 
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, 
          forge.util.hexToBytes(authorityKeyId)
        )
      )
    ]);

    // User notice and certificate policies
    const policies = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, 
        forge.asn1.oidToDer('1.3.6.1.5.5.7.2.2').getBytes()
      ),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.UTF8, false, "Data : " + blobData)
      ])
    ]);

    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, dataEncipherment: true },
      { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
      { id: '2.5.29.35', critical: false, value: authorityKeyIdentifier },
      { name: 'subjectKeyIdentifier' }, // Automatically generated
      { id: '2.5.29.32', critical: false, value: policies }
    ]);
    
    // Sign the certificate with CA private key
    cert.sign(caPrivateKey, forge.md.sha256.create());
    
    const certPem = forge.pki.certificateToPem(cert);
    
    res.json({ certificate: certPem });
  } catch (error) {
    console.error('Error in certificate generation:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});



app.get('/ca-cert', (req, res) => {
  try {
    const caCertPem = fs.readFileSync(caCertPath, 'utf8');
    res.set('Content-Type', 'application/x-pem-file');
    res.send(caCertPem);
  } catch (error) {
    console.error('Error serving CA certificate:', error);
    res.status(500).json({ error: 'Failed to serve CA certificate' });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Mock PKI server running on port ${PORT}`);
});