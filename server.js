const express = require('express');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const forge = require('node-forge');

const app = express();
app.use(express.json());

// Paths for CA files
const caDir = path.join(__dirname, 'ca');
const caKeyPath = path.join(caDir, 'ca.key');
const caCertPath = path.join(caDir, 'ca.crt');
const caConfigPath = path.join(caDir, 'openssl.cnf');

// Create CA directory if it doesn't exist
if (!fs.existsSync(caDir)) {
    fs.mkdirSync(caDir, { recursive: true });
}

// Create OpenSSL config if it doesn't exist
if (!fs.existsSync(caConfigPath)) {
    const opensslConfig = `
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ca

[ dn ]
CN = Mock CA
C = DE
ST = Mannheim
L = Mannheim
O = Mock PKI
OU = Mock PKI

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_end_cert ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
authorityInfoAccess = @aia

[ aia ]
caIssuers;URI = http://localhost:3000/ca.crt
`;
    fs.writeFileSync(caConfigPath, opensslConfig);
}

// Generate CA certificate if it doesn't exist
if (!fs.existsSync(caKeyPath) || !fs.existsSync(caCertPath)) {
    console.log('Generating new CA certificate...');
    
    // Generate CA private key (ECDSA P-256)
    execSync(`openssl ecparam -name prime256v1 -genkey -noout -out ${caKeyPath}`);
    
    // Generate CA certificate
    execSync(`openssl req -x509 -new -nodes -key ${caKeyPath} -sha256 -days 3650 -out ${caCertPath} -config ${caConfigPath}`);
}

// Endpoint to download CA certificate
app.get('/ca.crt', (req, res) => {
    res.download(caCertPath);
});

app.post('/sign-csr', (req, res) => {
    try {
        const { csr } = req.body;
        
        if (!csr) {
            return res.status(400).json({ error: 'CSR is required' });
        }

        // Create temporary files
        const tmpDir = path.join(caDir, 'tmp');
        if (!fs.existsSync(tmpDir)) {
            fs.mkdirSync(tmpDir, { recursive: true });
        }
        
        const csrPath = path.join(tmpDir, `${Date.now()}.csr`);
        const certPath = path.join(tmpDir, `${Date.now()}.crt`);
        const extPath = path.join(tmpDir, `${Date.now()}.ext`);

        // Write CSR to file
        fs.writeFileSync(csrPath, csr);

        // Create extensions file with AIA
        const serviceCardId = "SC123456";
        const userRole = "technician";
        const info = Buffer.from(JSON.stringify({
            serviceCardId,
            userRole,
            timestamp: new Date().toISOString()
        })).toString('base64');

        const extensions = `
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityInfoAccess = caIssuers;URI:http://localhost:3000/ca.crt
certificatePolicies = @policies

[policies]
policyIdentifier = 1.3.6.1.5.5.7.2.2
CPS.1 = ${info}
`;
        fs.writeFileSync(extPath, extensions);

        // Sign the CSR
        execSync(`openssl x509 -req -in ${csrPath} -CA ${caCertPath} -CAkey ${caKeyPath} -CAcreateserial \
            -out ${certPath} -days 365 -sha256 -extfile ${extPath}`);

        // Read the signed certificate
        const cert = fs.readFileSync(certPath, 'utf8');
        
        // Clean up temporary files
        fs.unlinkSync(csrPath);
        fs.unlinkSync(certPath);
        fs.unlinkSync(extPath);

        res.json({
            certificate: cert,
            message: "Certificate signed successfully. CA certificate can be downloaded from /ca.crt"
        });
    } catch (error) {
        console.error('Error signing CSR:', error);
        res.status(500).json({ error: 'Internal server error', details: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Mock PKI server running on port ${PORT}`);
    console.log(`CA certificate available at: http://localhost:${PORT}/ca.crt`);
});