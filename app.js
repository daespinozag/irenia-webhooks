const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const PRIVATE_KEY = process.env.FLOW_PRIVATE_KEY;

// --- FUNCIONES DE CIFRADO CORREGIDAS ---

const decryptRequest = (body, privateKey) => {
    const { encrypted_flow_data, encrypted_aes_key, initial_vector } = body;

    try {
        // 1. Descifrar la llave AES
        const decryptedAesKey = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            Buffer.from(encrypted_aes_key, "base64")
        );

        // 2. Preparar datos cifrados
        const encryptedBuffer = Buffer.from(encrypted_flow_data, "base64");
        const tag = encryptedBuffer.slice(-16);
        const ciphertext = encryptedBuffer.slice(0, -16);

        const decipher = crypto.createDecipheriv(
            "aes-128-gcm",
            decryptedAesKey,
            Buffer.from(initial_vector, "base64")
        );
        decipher.setAuthTag(tag);

        let decrypted = decipher.update(ciphertext, "base64", "utf8");
        decrypted += decipher.final("utf8");

        return {
            decryptedBody: JSON.parse(decrypted),
            aesKeyBuffer: decryptedAesKey,
        };
    } catch (error) {
        throw new Error("Fallo en RSA o AES-GCM: " + error.message);
    }
};

const encryptResponse = (response, aesKey, iv) => {
    const ivBuffer = Buffer.from(iv, "base64");
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, ivBuffer);

    // Cifrar el JSON como Buffer
    const plaintext = JSON.stringify(response);
    const ciphertext = Buffer.concat([
        cipher.update(plaintext, "utf8"),
        cipher.final(),
    ]);

    // Obtener el Tag de 16 bytes
    const tag = cipher.getAuthTag();

    // CONCATENAR BINARIO (Cipher + Tag) y luego pasar a Base64
    return Buffer.concat([ciphertext, tag]).toString("base64");
};

// --- RUTAS ---

app.all('/', (req, res) => res.status(200).send("Irenia Online"));

app.get(['/webhook', '/webhook/'], (req, res) => {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
        return res.status(200).send(challenge);
    }
    res.sendStatus(403);
});

app.post(['/webhook', '/webhook/'], async (req, res) => {
    const body = req.body;

    if (body.action === 'ping') {
        return res.status(200).send({ data: { status: "active" } });
    }

    if (body.encrypted_flow_data) {
        try {
            // Descifrado
            const { decryptedBody, aesKeyBuffer } = decryptRequest(body, PRIVATE_KEY);
            console.log("Flow Data:", decryptedBody);

            // Respuesta estándar para pasar el Health Check
            const responsePayload = {
                version: "3.0",
                screen: "SUCCESS",
                data: { 
                    extension_message_response: { 
                        params: { "status": "completed" } 
                    } 
                }
            };

            // Cifrado de respuesta (USANDO EL MISMO IV DE LA PETICIÓN)
            const encryptedResponse = encryptResponse(
                responsePayload,
                aesKeyBuffer,
                body.initial_vector
            );

            return res.status(200).send(encryptedResponse);

        } catch (err) {
            console.error("DEBUG - Error de descifrado:", err.message);
            // Enviamos el error detallado para saber qué falla exactamente en los logs
            return res.status(500).send(`Error: ${err.message}`);
        }
    }

    if (body.object === 'whatsapp_business_account') {
        return res.status(200).send('EVENT_RECEIVED');
    }

    res.sendStatus(404);
});

app.listen(PORT, () => console.log(`Puerto: ${PORT}`));