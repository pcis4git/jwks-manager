import fs from 'fs';
import forge from 'node-forge';
import { pem2jwk, jwk2pem } from 'pem-jwk';
import { RSA_JWK } from 'pem-jwk';
import { SecretsManagerClient, GetSecretValueCommand, PutSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import os from 'os';
import cors from 'cors';
import cluster, { Worker } from 'cluster';
import express, { Request, Response } from 'express';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';



export async function processSecret() {

    const secretValue = await loadSecret();
    let recentJWK = findLatestJWK(secretValue);
    let newlyJWK  = generateNewJWK();
    console.log(JSON.stringify(recentJWK, null, 2));
    console.log(JSON.stringify(newlyJWK,  null, 2));

    const jwks = {
        keys: [
            recentJWK['private'],
            recentJWK['public'],
            newlyJWK['private'],
            newlyJWK['public']
        ]
      };

    const jwksContent = JSON.stringify(jwks, null, 2);
    fs.writeFileSync('renewed-jwks.json', jwksContent);  

    await updateSecret(jwksContent);

  }
  
  async function loadSecret(): Promise<string> {
    dotenv.config();
    const secretName = process.env.secretName || '';
    let secretValue : string = '';
  
    try {
      const client = new SecretsManagerClient({ region: "ca-central-1" });
      const input = {
        SecretId: secretName,
        VersionStage: "AWSCURRENT", 
      }
      const command = new GetSecretValueCommand( input );
      const response = await client.send(command);
      secretValue = response.SecretString || '';
    } 
    catch (error) {
      console.error("Error fetching secret:", error);
      throw error;
    }

    return secretValue;
  } 

  async function updateSecret(secretValue : string) {
    dotenv.config();
    const secretName = process.env.secretName || '';
  
    try {
      const client = new SecretsManagerClient({ region: "ca-central-1" });
      const input = {
        SecretId: secretName,
        SecretString: secretValue
      }
      const command = new PutSecretValueCommand( input );
      const response = await client.send(command);
    } 
    catch (error) {
      console.error("Error updating secret:", error);
      throw error;
    }
  }


  function findLatestJWK( jwksContent : string ) : any {
  
      const secretObject = JSON.parse(jwksContent);
  
      let sorting: { [key: string]: any } = {};
      let kids : string[] = [];
  
      secretObject.keys.forEach((keyEntry : any ) => {        
         let kid : string = keyEntry.kid;
         console.log(`KID: ${kid}`);
  
         var jwkType = 'public';
         if( 'd' in keyEntry ) {
            jwkType = 'private';  
         }
  
         if( kid in sorting ) {       
            const item = sorting[kid];
            item[jwkType] = keyEntry;
         }
         else {
            const item : { [key: string]: any } = {};
            item[jwkType] = keyEntry;
  
            sorting[kid] = item;
            kids.push(kid); 
         }        
      });
  
      kids.sort();
  
//      console.log(JSON.stringify(sorting, null, 2));
      console.log(kids);
      
      let deleteKid : string = kids[0];
      let latestKid : string = kids[kids.length - 1];
      
      delete sorting[kids[0]];
      let latestJWK = sorting[latestKid];
      return latestJWK;  
  }

  function generateNewJWK() : any {

    const keyPair    = forge.pki.rsa.generateKeyPair({bits: 2048});
    const privateKey = forge.pki.privateKeyToPem(keyPair.privateKey);
    const publicKey  = forge.pki.publicKeyToPem(keyPair.publicKey);
    const x509Cert   = forge.pki.createCertificate();
    
    //console.log(privateKey);
    
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
    const jwkPrivateKey = pem2jwk(privateKey);
    const jwkPublicKey  = pem2jwk(publicKey);
    const kid = getCurrentTimeFormatted();
    jwkPrivateKey.kid = kid;
    jwkPublicKey.kid = kid;
    
    const pkcs8PrivateKey = generatePKCS8PrivateKey(keyPair);
    jwkPrivateKey.pkcs8 = pkcs8PrivateKey;
    jwkPrivateKey.pkcs1 = privateKey;    
    certPem = certPem.replace(/\r/g, '');
    certPem = certPem.replace(/\n/g, '');
    jwkPrivateKey.cert = certPem;

    
    //console.log(certPem);
    
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

function generatePKCS8PrivateKey(keyPair: any) : string {
  const privateKey = keyPair.privateKey;
  const asn1PrivateKey = forge.pki.privateKeyToAsn1(privateKey);
  const pkcs8 = forge.pki.wrapRsaPrivateKey(asn1PrivateKey);
  const derPkcs8 = forge.asn1.toDer(pkcs8).getBytes();
  const pem = `-----BEGIN PRIVATE KEY-----\n${forge.util.encode64(derPkcs8)}\n-----END PRIVATE KEY-----`;
  return pem;
}