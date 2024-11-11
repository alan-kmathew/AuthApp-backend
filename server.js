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

app.post('/sign-csr', (req, res) => {
  try {
    const { publicKey, subject } = req.body;
    console.log('Received Public Key:', publicKey);

    if (!publicKey) {
      return res.status(400).json({ error: 'Public key is required' });
    }

    const publicKeyObj = forge.pki.publicKeyFromPem(publicKey);

    const cert = forge.pki.createCertificate();
    cert.publicKey = publicKeyObj;
    cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    
    const attrs = [{
      name: 'commonName',
      value: subject.commonName
    }, {
      name: 'organizationName',
      value: subject.organizationName
    }, {
      name: 'countryName',
      value: subject.countryName
    }];
    
    cert.setSubject(attrs);
    cert.setIssuer(caCertificate.subject.attributes);

    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, dataEncipherment: true },
      { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
      { name: 'subjectKeyIdentifier' }, // Automatically generated
      { name: 'authorityKeyIdentifier', keyIdentifier: true, authorityCertIssuer: true, serialNumber: true }
    ]);
    
    cert.sign(caPrivateKey, forge.md.sha256.create());
    
    const certPem = forge.pki.certificateToPem(cert);
    
    res.json({ certificate: certPem });
  } catch (error) {
    console.error('Error signing public key:', error);
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