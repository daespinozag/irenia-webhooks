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
        // 1. Descifrar la llave AES con RSA
        const decryptedAesKey = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            Buffer.from(encrypted_aes_key, "base64")
        );

        // 2. Preparar datos cifrados (Ciphertext + Tag)
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
    } catch (error) {
        throw new Error("Fallo en descifrado: " + error.message);
    }
};

const encryptResponse = (response, aesKey, iv) => {
    try {
        const ivBuffer = Buffer.from(iv, "base64");
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, ivBuffer);

        // Convertir el JSON a string UTF-8 (Sugerencia 1: Manejo robusto de encoding)
        const plaintext = JSON.stringify(response);
        
        const ciphertext = Buffer.concat([
            cipher.update(plaintext, "utf8"),
            cipher.final(),
        ]);

        const tag = cipher.getAuthTag();

        // Concatenar Ciphertext + Tag y pasar a Base64 (Lo que Meta espera)
        return Buffer.concat([ciphertext, tag]).toString("base64");
    } catch (error) {
        throw new Error("Error en cifrado de respuesta: " + error.message);
    }
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

    // Health check de Meta
    if (body.action === 'ping') {
        return res.status(200).send({ data: { status: "active" } });
    }

    if (body.encrypted_flow_data) {
        try {
            const { decryptedBody, aesKeyBuffer } = decryptRequest(body, PRIVATE_KEY);
            console.log("Datos recibidos del Flow:", decryptedBody);

            // Sugerencia 2: Payload alineado con data_api_version: "3.0"
            const responsePayload = {
                version: "3.0", 
                screen: "SUCCESS", // Esto cierra el flow tras el login
                data: { 
                    extension_message_response: { 
                        params: { 
                            "status": "completed",
                            "user": decryptedBody.email || "unknown" 
                        } 
                    } 
                }
            };

            const encryptedResponse = encryptResponse(
                responsePayload,
                aesKeyBuffer,
                body.initial_vector
            );

            return res.status(200).send(encryptedResponse);

        } catch (err) {
            console.error("ERROR CRÍTICO:", err.message);
            return res.status(500).send(`Error: ${err.message}`);
        }
    }

    if (body.object === 'whatsapp_business_account') {
        return res.status(200).send('EVENT_RECEIVED');
    }

    res.sendStatus(404);
});

app.listen(PORT, () => console.log(`Servidor corriendo en puerto: ${PORT}`));