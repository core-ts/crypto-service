"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
  function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
  return new (P || (P = Promise))(function (resolve, reject) {
    function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
    function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
    function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
    step((generator = generator.apply(thisArg, _arguments || [])).next());
  });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
  var _ = { label: 0, sent: function () { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
  return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function () { return this; }), g;
  function verb(n) { return function (v) { return step([n, v]); }; }
  function step(op) {
    if (f) throw new TypeError("Generator is already executing.");
    while (_) try {
      if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
      if (y = 0, t) op = [op[0] & 2, t.value];
      switch (op[0]) {
        case 0: case 1: t = op; break;
        case 4: _.label++; return { value: op[1], done: false };
        case 5: _.label++; y = op[1]; op = [0]; continue;
        case 7: op = _.ops.pop(); _.trys.pop(); continue;
        default:
          if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
          if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
          if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
          if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
          if (t[2]) _.ops.pop();
          _.trys.pop(); continue;
      }
      op = body.call(thisArg, _);
    } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
    if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
  }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
  return (mod && mod.__esModule) ? mod : { "default": mod };
};
var __importStar = (this && this.__importStar) || function (mod) {
  if (mod && mod.__esModule) return mod;
  var result = {};
  if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
  result["default"] = mod;
  return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
var atob_1 = __importDefault(require("atob"));
var btoa_1 = __importDefault(require("btoa"));
var forge = __importStar(require("node-forge"));
var CryptoService = /** @class */ (function () {
  function CryptoService(encryption, hashKey) {
    this.encryption = encryption;
    this.hashKey = hashKey;
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
  CryptoService.prototype.exchangeKeypair = function (pk) {
    return __awaiter(this, void 0, void 0, function () {
      var shareKeyServ, saltServ, data, rsaEncrypted;
      return __generator(this, function (_a) {
        shareKeyServ = forge.random.getBytesSync(32);
        saltServ = forge.random.getBytesSync(32);
        data = {
          shareKey: shareKeyServ,
          salt: saltServ,
        };
        rsaEncrypted = this.encrypt(pk, JSON.stringify(data));
        return [2 /*return*/, {
          rsaEncrypted: rsaEncrypted,
          data: data,
        }];
      });
    });
  };
  CryptoService.prototype.encryptAESMessage = function (aesKey, salt, dataJSON, options) {
    return __awaiter(this, void 0, void 0, function () {
      var convertKey2Bytes, aesEncrypted, hash, reqData, base64;
      return __generator(this, function (_a) {
        if (this.encryption) {
          convertKey2Bytes = options && options.convertKey2Bytes;
          aesEncrypted = this.encryptAES(convertKey2Bytes ? atob_1.default(aesKey) : aesKey, dataJSON);
          hash = this.hashHMAC(convertKey2Bytes ? atob_1.default(salt) : salt, aesEncrypted);
          reqData = "" + hash + aesEncrypted;
          base64 = btoa_1.default(reqData);
          return [2 /*return*/, base64];
        }
        else {
          return [2 /*return*/, dataJSON];
        }
        return [2 /*return*/];
      });
    });
  };
  CryptoService.prototype.decryptAESMessage = function (messageEncrypted, clientShKey, clientSalt, options) {
    return __awaiter(this, void 0, void 0, function () {
      var convertKey2Bytes, hashData, output, hmacResult, ivRes, msg, decrypted;
      return __generator(this, function (_a) {
        switch (_a.label) {
          case 0:
            if (!this.encryption) return [3 /*break*/, 2];
            if (options && options.isEncoded64) {
              messageEncrypted = atob_1.default(messageEncrypted);
            }
            convertKey2Bytes = options && options.convertKey2Bytes;
            hashData = messageEncrypted.substring(0, 64);
            output = messageEncrypted.substring(64, messageEncrypted.length);
            hmacResult = this.hashHMAC(convertKey2Bytes ? atob_1.default(clientSalt) : clientSalt, output);
            if (hashData !== hmacResult) {
              return [2 /*return*/, ''];
            }
            ivRes = output.substring(0, 16);
            msg = output.substring(16, output.length);
            return [4 /*yield*/, this.decryptAES(convertKey2Bytes ? atob_1.default(clientShKey) : clientShKey, msg, ivRes)];
          case 1:
            decrypted = _a.sent();
            return [2 /*return*/, decrypted];
          case 2: return [2 /*return*/, messageEncrypted];
        }
      });
    });
  };
  CryptoService.prototype.encrypt = function (pk, message) {
    var publicKey = forge.pki.publicKeyFromPem(pk);
    var encrypted = publicKey.encrypt(message, 'RSA-OAEP', {
      md: forge.md.sha256.create(),
    });
    var res = btoa_1.default(encrypted);
    return res;
  };
  CryptoService.prototype.decrypt = function (sk, data) {
    var privateKey = forge.pki.privateKeyFromPem(sk);
    var msg = forge.util.decode64(data);
    var decrypted = privateKey.decrypt(msg, 'RSA-OAEP', {
      md: forge.md.sha256.create(),
    });
    return decrypted;
  };
  CryptoService.prototype.encryptAES = function (key, message) {
    var iv = forge.random.getBytesSync(16);
    var cipher = forge.cipher.createCipher('AES-CBC', key);
    cipher.start({ iv: iv });
    cipher.update(forge.util.createBuffer(message, 'utf8'));
    cipher.finish();
    var encrypted = cipher.output;
    var strEncrypted = Buffer.from(encrypted.getBytes()).toString();
    var result = iv + strEncrypted;
    return result;
  };
  CryptoService.prototype.decryptAES = function (key, ciphertext, iv) {
    var decipher = forge.cipher.createDecipher('AES-CBC', key);
    decipher.start({ iv: iv });
    decipher.update(forge.util.createBuffer(ciphertext));
    decipher.finish();
    return decipher.output.toString();
  };
  CryptoService.prototype.hashHMAC = function (key, data) {
    var hmac1 = forge.hmac.create();
    hmac1.start('sha256', key);
    hmac1.update(data);
    return hmac1.digest().toHex();
  };
  CryptoService.prototype.hashData = function (text) {
    var crypto = require('crypto');
    var shasum = crypto.createHash('sha256');
    var msg = text + this.hashKey;
    shasum.update(msg);
    var hash = shasum.digest('hex');
    return hash;
  };
  return CryptoService;
}());
exports.CryptoService = CryptoService;
function genUuid() {
  var crypto = require('crypto');
  var id = crypto.randomBytes(16).toString('hex');
  return id;
}
exports.genUuid = genUuid;
function getTokenExpirationTime(now, tokenAge) {
  return (now.getTime() + tokenAge) / 1000;
}
exports.getTokenExpirationTime = getTokenExpirationTime;
function minuteToMillisec(min) {
  var msInOneMin = 1000 * 60;
  return min * msInOneMin;
}
exports.minuteToMillisec = minuteToMillisec;
