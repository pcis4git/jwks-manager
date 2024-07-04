import forge from 'node-forge';
import os from 'os';
import cors from 'cors';
import cluster, { Worker } from 'cluster';
import express, { Request, Response } from 'express';
import bodyParser from 'body-parser';
import { RSA_JWK, pem2jwk, jwk2pem } from 'pem-jwk';
import dotenv from 'dotenv';
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { processSecret } from './renewjwks';
import { generateNewJWKS } from './newjwks';

processSecret();

//generateNewJWKS();
