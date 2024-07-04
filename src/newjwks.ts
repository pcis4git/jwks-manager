import fs from 'fs';
import forge from 'node-forge';
import { pem2jwk, jwk2pem } from 'pem-jwk';
import { RSA_JWK } from 'pem-jwk';
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

generateNewJWKS();

export function generateNewJWKS() : any {

    const keyPair    = forge.pki.rsa.generateKeyPair({bits: 2048});
    const privateKey = forge.pki.privateKeyToPem(keyPair.privateKey);
    const publicKey  = forge.pki.publicKeyToPem(keyPair.publicKey);
    const x509Cert   = forge.pki.createCertificate();
    
    console.log(privateKey);
    
    x509Cert.publicKey = keyPair.publicKey;
    x509Cert.serialNumber = Date.now() + '';
    x509Cert.validity.notBefore = new Date();
    x509Cert.validity.notAfter = new Date();
    x509Cert.validity.notAfter.setFullYear(x509Cert.validity.notBefore.getFullYear() + 1);
    
    const attrs = [
      {
        name: 'commonName',
        value: 'OneAccessGateway'
      }, 
      {
        name: 'countryName',
        value: 'CA'
      }, 
      {
        shortName: 'ST',
        value: 'ON'
      }, 
      {
        shortName: 'OU',
        value: 'OH'
     }
    ];
    
    x509Cert.setSubject(attrs);
    x509Cert.setIssuer(attrs);
    
    x509Cert.sign(keyPair.privateKey, forge.md.sha256.create());
    
    // Convert the certificate to PEM format
    let certPem = forge.pki.certificateToPem(x509Cert);
    certPem = certPem.replace(/\r/g, '');
    certPem = certPem.replace(/\n/g, '');
    const jwkPrivateKey = pem2jwk(privateKey);
    const jwkPublicKey  = pem2jwk(publicKey);

    const kid = getCurrentTimeFormatted();
    jwkPrivateKey.kid = kid;
    jwkPublicKey.kid = kid;
    jwkPrivateKey.private_key = privateKey;
    
    console.log(certPem);
    
    // Include the certificate in the JWK
    jwkPublicKey.x5c = certPem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n/g, '');
    
    const jwks = {
      keys: [jwkPrivateKey, jwkPublicKey]
    };
    const jwksContent = JSON.stringify(jwks, null, 2);
    fs.writeFileSync('jwks.json', jwksContent);


    const newJWK = {
      private : jwkPrivateKey,
      public  : jwkPublicKey
    }

    return newJWK;
}


function getCurrentTimeFormatted() : string {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0'); // January is 0!
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');

  return `${year}${month}${day}${hours}${minutes}${seconds}`;
}

