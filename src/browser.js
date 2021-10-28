/*
Convert  an ArrayBuffer into a string
from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
*/
function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}
/*
  Convert a string into an ArrayBuffer
  from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
  */
function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

/*
  Export the given key and write it into the "exported-key" space.
  */
async function exportPublicCryptoKey(key) {
  const exported = await crypto.subtle.exportKey("spki", key);
  const exportedAsString = ab2str(exported);
  const exportedAsBase64 = window.btoa(exportedAsString);
  const pemExported = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
  return pemExported;
}

/*
  Export the given key and write it into the "exported-key" space.
  */
async function exportPrivateCryptoKey(key) {
  const exported = await crypto.subtle.exportKey("pkcs8", key);
  const exportedAsString = ab2str(exported);
  const exportedAsBase64 = window.btoa(exportedAsString);
  const pemExported = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
  return pemExported;
}

/**
  Import the key given key
 */
function importPrivateKey(pem) {
  // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = pem.substring(
    pemHeader.length,
    pem.length - pemFooter.length
  );
  // base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);

  return crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "RSA-PSS",
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

const main = async () => {
  // key generation
  const generated = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  console.log(generated);

  const message = "Only You should now this";
  // byte stream with UTF-8 encoding.
  const encoder = new TextEncoder();
  const encondedMessage = encoder.encode(message);

  console.log("Message before encription: ", message);

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    generated.publicKey,
    encondedMessage
  );

  console.log("encrypted: ", encrypted);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    generated.privateKey,
    encrypted
  );

  console.log("decrypted: ", Buffer.from(decrypted).toString());

  // Export public Key part

  const exported = await exportPublicCryptoKey(generated.publicKey);
  console.log({ exported });
};

main();
