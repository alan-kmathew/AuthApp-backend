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
    value: 'US'
  }, {
    shortName: 'ST',
    value: 'California'
  }, {
    name: 'localityName',
    value: 'San Francisco'
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

app.post('/sign-csr', (req, res) => {
  try {
    const { csr } = req.body;
    
    if (!csr) {
      return res.status(400).json({ error: 'CSR is required' });
    }
    
    const csrObj = forge.pki.certificationRequestFromPem(csr);
    
    // Verify the CSR
    if (!csrObj.verify()) {
      return res.status(400).json({ error: 'Invalid CSR' });
    }
    
    // Create a new certificate
    const cert = forge.pki.createCertificate();
    cert.publicKey = csrObj.publicKey;
    cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    
    cert.setSubject(csrObj.subject.attributes);
    cert.setIssuer(caCertificate.subject.attributes);
    
    cert.setExtensions([{
      name: 'basicConstraints',
      cA: false
    }, {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true,
      dataEncipherment: true
    }, {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true
    }, {
      name: 'authorityKeyIdentifier'
    }]);
    
    // Sign the certificate with the CA private key
    cert.sign(caPrivateKey, forge.md.sha256.create());
    
    // Convert the certificate to PEM format
    const certPem = forge.pki.certificateToPem(cert);
    
    res.json({ certificate: certPem });
  } catch (error) {
    console.error('Error signing CSR:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Mock PKI server running on port ${PORT}`);
});