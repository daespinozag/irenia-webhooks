const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

// VARIABLES DE ENTORNO
const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const PRIVATE_KEY = process.env.FLOW_PRIVATE_KEY; // Tu nueva llave privada de Render

// 1. VERIFICACIÓN DEL WEBHOOK (Indispensable para Meta)
app.get('/webhook', (req, res) => {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
        console.log('WEBHOOK_VERIFIED');
        res.status(200).send(challenge);
    } else {
        res.sendStatus(403);
    }
});

// 2. PROCESAMIENTO DE MENSAJES Y FLOWS
app.post('/webhook', async (req, res) => {
    const body = req.body;

    // --- LÓGICA DE WHATSAPP FLOWS ---
    // Si Meta envía un 'ping' para verificar el endpoint del Flow
    if (body.action === 'ping') {
        return res.status(200).send({ data: { status: "active" } });
    }

    // Si el body contiene datos de un Flow (intercambio de datos)
    if (body.decrypted_payload) {
        try {
            const flowData = body.decrypted_payload;
            
            if (flowData.screen === 'SIGN_UP') {
                const { email, first_name } = flowData.data;
                console.log(`Usuario registrado vía Flow: ${first_name} (${email})`);

                // AQUÍ DISPARAS ELEVENLABS EN EL FUTURO
                
                return res.status(200).send({
                    version: "3.0",
                    screen: "SUCCESS",
                    data: { extension_message_response: { params: { "status": "success" } } }
                });
            }
        } catch (err) {
            console.error("Error en el Flow:", err);
            return res.sendStatus(500);
        }
    }

    // --- LÓGICA DE MENSAJES NORMALES (IRENIA) ---
    if (body.object === 'whatsapp_business_account') {
        const message = body.entry?.[0]?.changes?.[0]?.value?.messages?.[0];
        if (message) {
            console.log(`Mensaje de ${message.from}: ${message.text?.body || 'Mensaje no textual'}`);
            // Aquí es donde Irenia procesa el texto y responde con ElevenLabs
        }
        return res.status(200).send('EVENT_RECEIVED');
    }

    res.sendStatus(404);
});

app.listen(PORT, () => {
    console.log(`Irenia Server en puerto ${PORT}`);
});
