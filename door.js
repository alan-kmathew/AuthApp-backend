const forge = require('node-forge');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

class MTLSTestClient {
  constructor() {
    this.mockCAUrl = 'http://localhost:3000';
    this.mtlsServerUrl = 'https://localhost:3443';
    
    // Paths for storing certificates
    this.clientCertPath = path.join(__dirname, 'client_cert.pem');
    this.clientKeyPath = path.join(__dirname, 'client_key.pem');
    this.caCertPath = path.join(__dirname, 'ca_cert.pem');
  }

  async generateKeyAndCSR() {
    console.log('Generating key pair and CSR...');
    
    // Generate key pair
    const keys = forge.pki.rsa.generateKeyPair(2048);
    this.privateKey = keys.privateKey;
    
    // Create CSR
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = keys.publicKey;
    csr.setSubject([{
      name: 'commonName',
      value: 'Test Client'
    }, {
      name: 'organizationName',
      value: 'MTLS Test'
    }]);
    
    // Sign CSR
    csr.sign(this.privateKey);
    
    // Convert to PEM format
    return forge.pki.certificationRequestToPem(csr);
  }

  makeHttpRequest(options, postData = null) {
    return new Promise((resolve, reject) => {
      const protocol = options.protocol === 'https:' ? https : http;
      
      const req = protocol.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve({
                statusCode: res.statusCode,
                data: JSON.parse(data)
              });
            } catch {
              resolve({
                statusCode: res.statusCode,
                data: data
              });
            }
          } else {
            reject(new Error(`Request failed with status ${res.statusCode}: ${data}`));
          }
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      if (postData) {
        req.write(postData);
      }
      req.end();
    });
  }

  async getSignedCertificate(csrPem) {
    console.log('Getting certificate signed by mock CA...');
    
    try {
      const postData = JSON.stringify({
        csr: csrPem
      });

      const options = {
        protocol: 'http:',
        hostname: 'localhost',
        port: 3000,
        path: '/sign-csr',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        }
      };

      const response = await this.makeHttpRequest(options, postData);
      return response.data.certificate;
    } catch (error) {
      console.error('Error getting certificate signed:', error);
      throw error;
    }
  }

  async getCACertificate() {
    console.log('Fetching CA certificate...');
    
    try {
      const options = {
        protocol: 'http:',
        hostname: 'localhost',
        port: 3000,
        path: '/ca-cert',
        method: 'GET'
      };

      const response = await this.makeHttpRequest(options);
      return response.data;
    } catch (error) {
      console.error('Error getting CA certificate:', error);
      throw error;
    }
  }

  saveCertificates(clientCert, caCert) {
    // Save client certificate
    fs.writeFileSync(this.clientCertPath, clientCert);
    console.log('Client certificate saved to:', this.clientCertPath);
    
    // Save private key
    fs.writeFileSync(this.clientKeyPath, forge.pki.privateKeyToPem(this.privateKey));
    console.log('Private key saved to:', this.clientKeyPath);
    
    // Save CA certificate
    fs.writeFileSync(this.caCertPath, caCert);
    console.log('CA certificate saved to:', this.caCertPath);
  }

  async testMTLSConnection() {
    console.log('\nTesting MTLS connection to server...');
    
    try {
      const options = {
        protocol: 'https:',
        hostname: 'localhost',
        port: 3443,
        path: '/api/protected',
        method: 'GET',
        key: fs.readFileSync(this.clientKeyPath),
        cert: fs.readFileSync(this.clientCertPath),
        ca: fs.readFileSync(this.caCertPath),
        rejectUnauthorized: true
      };

      const response = await this.makeHttpRequest(options);
      console.log('\nMTLS Connection Successful!');
      console.log('Status Code:', response.statusCode);
      
      if (response.data.embeddedData) {
        console.log('\n=== Embedded Certificate Data ===');
        console.log('Service Card ID:', response.data.embeddedData.serviceCardId);
        console.log('User Role:', response.data.embeddedData.userRole);
        console.log('Timestamp:', response.data.embeddedData.timestamp);
        console.log('\nOriginal Base64:', response.data.decodedInfo.original.base64);
        console.log('Decoded String:', response.data.decodedInfo.original.decoded);
        console.log('================================\n');
      }
      
      console.log('\nFull Server Response:', JSON.stringify(response.data, null, 2));
      
    } catch (error) {
      console.error('\nMTLS Connection Failed!');
      console.error('Error:', error.message);
      throw error;
    }
}

  async testHealthEndpoint() {
    console.log('\nTesting health endpoint (no MTLS)...');
    
    try {
      const options = {
        protocol: 'https:',
        hostname: 'localhost',
        port: 3443,
        path: '/health',
        method: 'GET',
        ca: fs.readFileSync(this.caCertPath),
        rejectUnauthorized: true
      };

      const response = await this.makeHttpRequest(options);
      console.log('Health Check Status:', response.statusCode);
      console.log('Health Check Response:', response.data);
      
    } catch (error) {
      console.error('Health check failed:', error);
      // Continue with the test even if health check fails
    }
  }

  async runFullTest() {
    try {
      console.log('\n=== Starting Full MTLS Test ===\n');
      
      // Step 1: Generate key pair and CSR
      console.log('Step 1: Generating key pair and CSR');
      const csrPem = await this.generateKeyAndCSR();
      console.log('✓ Key pair and CSR generated\n');
      
      // Step 2: Get CA certificate
      console.log('Step 2: Getting CA certificate');
      const caCert = await this.getCACertificate();
      console.log('✓ CA certificate received\n');
      
      // Step 3: Get CSR signed
      console.log('Step 3: Getting CSR signed');
      const clientCert = await this.getSignedCertificate(csrPem);
      console.log('✓ Certificate signed by CA\n');
      
      // Step 4: Save all certificates
      console.log('Step 4: Saving certificates');
      this.saveCertificates(clientCert, caCert);
      console.log('✓ All certificates saved\n');
      
      // Step 5: Test health endpoint
      console.log('Step 5: Testing health endpoint');
      await this.testHealthEndpoint();
      console.log('✓ Health check completed\n');
      
      // Step 6: Test MTLS connection
      console.log('Step 6: Testing MTLS connection');
      await this.testMTLSConnection();
      console.log('✓ MTLS test completed\n');
      
      console.log('=== Full Test Completed Successfully ===');
      
    } catch (error) {
      console.error('\n=== Test Failed ===');
      console.error('Error:', error.message);
      console.error('\nStack trace:', error.stack);
    }
  }

  displayCertificateInfo() {
    try {
      console.log('\n=== Certificate Information ===\n');
      
      // Display client certificate info
      const clientCert = forge.pki.certificateFromPem(
        fs.readFileSync(this.clientCertPath, 'utf8')
      );
      console.log('Client Certificate:');
      console.log('- Subject:', clientCert.subject.getField('CN').value);
      console.log('- Organization:', clientCert.subject.getField('O').value);
      console.log('- Valid From:', clientCert.validity.notBefore);
      console.log('- Valid To:', clientCert.validity.notAfter);
      
      // Display CA certificate info
      const caCert = forge.pki.certificateFromPem(
        fs.readFileSync(this.caCertPath, 'utf8')
      );
      console.log('\nCA Certificate:');
      console.log('- Subject:', caCert.subject.getField('CN').value);
      console.log('- Organization:', caCert.subject.getField('O').value);
      
    } catch (error) {
      console.error('Error displaying certificate info:', error);
    }
  }
}

// Run the test
console.log('Starting MTLS Test Client...');
const testClient = new MTLSTestClient();
testClient.runFullTest().then(() => {
  testClient.displayCertificateInfo();
}).catch(console.error);