import atob from 'atob';
import btoa from 'btoa';
import * as forge from 'node-forge';

export interface KeypairResult {
  rsaEncrypted: string;
  data: {
    shareKey: string;
    salt: string;
  };
}

export interface CryptoOption {
  isEncoded64?: boolean;
  convertKey2Bytes?: boolean;
}

export interface CryptoPort {
  exchangeKeypair: (pk: string) => Promise<KeypairResult>;
  encryptAESMessage: (aesKey: string, salt: string, dataJSON: string,  options?: CryptoOption) => Promise<string>;
  decryptAESMessage: <T>(messageEncrypted: string, clientShKey: string, clientSalt: string, options?: CryptoOption) => Promise<T | string>;
  encrypt: (pk: any, message: string) => string;
  decrypt: (sk: any, data: string) => string;
  encryptAES: (key: string, message: string) => string;
  decryptAES: (key: string, ciphertext: string, iv: string) => string;
  hashHMAC: (key: string, data: string) => string;
  hashData: (text: string) => string;
}

export class CryptoService {
  constructor(private encryption: boolean, private hashKey: string) {
    this.exchangeKeypair = this.exchangeKeypair.bind(this);
    this.encryptAESMessage = this.encryptAESMessage.bind(this);
    this.decryptAESMessage = this.decryptAESMessage.bind(this);
    this.encrypt = this.encrypt.bind(this);
    this.decrypt = this.decrypt.bind(this);
    this.encryptAES = this.encryptAES.bind(this);
    this.decryptAES = this.decryptAES.bind(this);
    this.hashHMAC = this.hashHMAC.bind(this);
    this.hashData = this.hashData.bind(this);
  }
  async exchangeKeypair(pk: string): Promise<KeypairResult> {
    const shareKeyServ = forge.random.getBytesSync(32);
    const saltServ = forge.random.getBytesSync(32);
    const data = {
      shareKey: shareKeyServ,
      salt: saltServ,
    };
    const rsaEncrypted = this.encrypt(pk, JSON.stringify(data));
    return {
      rsaEncrypted,
      data,
    };
  }
  async encryptAESMessage(aesKey: string, salt: string, dataJSON: string, options?: CryptoOption): Promise<string> {
    if (this.encryption) {
      const convertKey2Bytes = options && options.convertKey2Bytes;
      const aesEncrypted = this.encryptAES(
        convertKey2Bytes ? atob(aesKey) : aesKey,
        dataJSON,
      );
      const hash = this.hashHMAC(
        convertKey2Bytes ? atob(salt) : salt,
        aesEncrypted,
      );
      const reqData = `${hash}${aesEncrypted}`;
      const base64 = btoa(reqData);
      return base64;
    } else {
      return dataJSON;
    }
  }
  async decryptAESMessage<T>(messageEncrypted: string, clientShKey: string, clientSalt: string, options?: CryptoOption): Promise<T | string> {
    if (this.encryption) {
      if (options && options.isEncoded64) {
        messageEncrypted = atob(messageEncrypted);
      }
      const convertKey2Bytes = options && options.convertKey2Bytes;
      const hashData = messageEncrypted.substring(0, 64);
      const output = messageEncrypted.substring(64, messageEncrypted.length);
      const hmacResult = this.hashHMAC(
        convertKey2Bytes ? atob(clientSalt) : clientSalt,
        output,
      );

      if (hashData !== hmacResult) {
        return '';
      }

      const ivRes = output.substring(0, 16);
      const msg = output.substring(16, output.length);
      const decrypted = await this.decryptAES(
        convertKey2Bytes ? atob(clientShKey) : clientShKey,
        msg,
        ivRes,
      );
      return decrypted;
    } else {
      return messageEncrypted;
    }
  }
  encrypt(pk: any, message: string): string {
    const publicKey = forge.pki.publicKeyFromPem(pk);
    const encrypted = publicKey.encrypt(message, 'RSA-OAEP', {
      md: forge.md.sha256.create(),
    });
    const res = btoa(encrypted);
    return res;
  }
  decrypt(sk: any, data: string): string {
    const privateKey = forge.pki.privateKeyFromPem(sk);
    const msg = forge.util.decode64(data);
    const decrypted = privateKey.decrypt(msg, 'RSA-OAEP', {
      md: forge.md.sha256.create(),
    });
    return decrypted;
  }
  encryptAES(key: string, message: string): string {
    const iv = forge.random.getBytesSync(16);
    const cipher = forge.cipher.createCipher('AES-CBC', key);
    cipher.start({ iv });
    cipher.update(forge.util.createBuffer(message, 'utf8'));
    cipher.finish();
    const encrypted = cipher.output;

    const strEncrypted = Buffer.from(encrypted.getBytes()).toString();

    const result = iv + strEncrypted;

    return result;
  }
  decryptAES(key: string, ciphertext: string, iv: string): string {
    const decipher = forge.cipher.createDecipher('AES-CBC', key);
    decipher.start({ iv });
    decipher.update(forge.util.createBuffer(ciphertext));
    decipher.finish();
    return decipher.output.toString();
  }

  hashHMAC(key: string, data: string): string {
    const hmac1 = forge.hmac.create();
    hmac1.start('sha256', key);
    hmac1.update(data);

    return hmac1.digest().toHex();
  }

  hashData(text: string): string {
    const crypto = require('crypto');
    const shasum = crypto.createHash('sha256');
    const msg = text + this.hashKey;
    shasum.update(msg);
    const hash = shasum.digest('hex');
    return hash;
  }
}

export function genUuid(): string {
  const crypto = require('crypto');
  const id = crypto.randomBytes(16).toString('hex');
  return id;
}

export function getTokenExpirationTime(now: Date, tokenAge: number) {
  return (now.getTime() + tokenAge) / 1000;
}

export function minuteToMillisec(min: number) {
  const msInOneMin = 1000 * 60;
  return min * msInOneMin;
}
