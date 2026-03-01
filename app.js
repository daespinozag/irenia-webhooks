const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const PRIVATE_KEY = process.env.FLOW_PRIVATE_KEY;

// --- FUNCIONES DE CIFRADO PARA FLOWS ---

/**
 * Descifra la petición de WhatsApp Flow
 */
const decryptRequest = (body, privateKey) => {
    const { encrypted_flow_data, encrypted_aes_key, initial_vector } = body;

    // 1. Descifrar la llave AES simétrica con tu llave privada RSA
    const decryptedAesKey = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        Buffer.from(encrypted_aes_key, "base64")
    );

    // 2. Descifrar los datos del Flow usando AES-GCM
    const encryptedBuffer = Buffer.from(encrypted_flow_data, "base64");
    const tag = encryptedBuffer.slice(-16); // Los últimos 16 bytes son el tag
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
};

/**
 * Cifra la respuesta para que WhatsApp la acepte (Base64)
 */
const encryptResponse = (response, aesKey, iv) => {
    const ivBuffer = Buffer.from(iv, "base64");
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, ivBuffer);

    let encrypted = cipher.update(JSON.stringify(response), "utf8", "base64");
    encrypted += cipher.final("base64");

    const tag = cipher.getAuthTag().toString("base64");
    // WhatsApp espera el mensaje cifrado + el tag de autenticación, todo en base64
    return Buffer.from(encrypted + tag, "base64").toString("base64");
};

// --- RUTAS ---

app.all('/', (req, res) => {
    res.status(200).send("Irenia Server is Online");
});

// Verificación del Webhook (GET)
app.get(['/webhook', '/webhook/'], (req, res) => {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
        console.log('WEBHOOK_VERIFIED');
        return res.status(200).send(challenge);
    }
    res.sendStatus(403);
});

// Procesamiento de Flows y Mensajes (POST)
app.post(['/webhook', '/webhook/'], async (req, res) => {
    const body = req.body;

    // A. Respuesta al PING
    if (body.action === 'ping') {
        return res.status(200).send({ data: { status: "active" } });
    }

    // B. Lógica de WHATSAPP FLOWS (Datos Cifrados)
    if (body.encrypted_flow_data) {
        try {
            // Desciframos la petición para obtener la llave de sesión
            const { decryptedBody, aesKeyBuffer } = decryptRequest(body, PRIVATE_KEY);
            console.log("Datos del Flow descifrados:", decryptedBody);

            // Preparamos la respuesta que queremos dar
            const responsePayload = {
                version: "3.0",
                screen: "SUCCESS",
                data: { 
                    extension_message_response: { 
                        params: { "status": "completed" } 
                    } 
                }
            };

            // CIFRAMOS la respuesta usando la misma llave AES y el mismo IV
            const encryptedResponseBase64 = encryptResponse(
                responsePayload,
                aesKeyBuffer,
                body.initial_vector
            );

            // Enviamos el string Base64 directamente como cuerpo de la respuesta
            return res.status(200).send(encryptedResponseBase64);

        } catch (err) {
            console.error("Error procesando Flow cifrado:", err.message);
            return res.status(500).send("Error de descifrado");
        }
    }

    // C. Mensajes normales de WhatsApp
    if (body.object === 'whatsapp_business_account') {
        return res.status(200).send('EVENT_RECEIVED');
    }

    res.sendStatus(404);
});

app.listen(PORT, () => {
    console.log(`Irenia Server en puerto ${PORT}`);
});