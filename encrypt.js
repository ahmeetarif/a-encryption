process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const crypto = require('crypto');
const axios = require('axios');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
const publicKeyBase64 = Buffer.from(publicKeyDer).toString('base64');

(async () => {
    const response = await axios.get('https://localhost/api/test/encrypt', {
        headers: {
            'X-Public-Key': publicKeyBase64,
            'Authorization': 'Bearer BEARER'
        },
    });

    console.log('✅ Response Data:', response.data);
    console.log('✅ Response Headers:', response.headers);

    const { data } = response.data;

    const iv = response.headers['x-requested-iv'];
    const tag = response.headers['x-requested-tag'];
    const encryptedKey = response.headers['x-requested-encryption-key'];

    const decryptedAesKey = crypto.privateDecrypt(
        {
            key: privateKey.export({ type: 'pkcs1', format: 'pem' }),
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        Buffer.from(encryptedKey, 'base64')
    );

    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        decryptedAesKey,
        Buffer.from(iv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(tag, 'base64'));

    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(data, 'base64')),
        decipher.final(),
    ]);

    console.log('✅ Decrypted data:', decrypted.toString());
})();
