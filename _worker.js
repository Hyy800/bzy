// Helper: Convert ArrayBuffer to Uppercase Hex String
function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
        .toUpperCase();
}

// AES-CBC Encryption using Web Crypto API
// keyText: UTF-8 string for the key
// ivText: UTF-8 string for the IV
// plainText: The string to be encrypted
async function aesCbcEncrypt(keyText, ivText, plainText) {
    const encoder = new TextEncoder();
    
    const keyBytes = encoder.encode(keyText);
    const ivBytes = encoder.encode(ivText);

    if (![16, 24, 32].includes(keyBytes.length)) {
        throw new Error(`Invalid AES key length: ${keyBytes.length} bytes. Must be 16, 24, or 32 bytes.`);
    }
    if (ivBytes.length !== 16) {
        throw new Error(`Invalid IV length for AES-CBC: ${ivBytes.length} bytes. Must be 16 bytes.`);
    }

    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-CBC", length: keyBytes.length * 8 },
        false, // exportable
        ["encrypt"] // key usages
    );

    const plainTextEncoded = encoder.encode(plainText);

    const encryptedBuffer = await crypto.subtle.encrypt(
        {
            name: "AES-CBC",
            iv: ivBytes
        },
        cryptoKey,
        plainTextEncoded
    );

    return bufferToHex(encryptedBuffer);
}

// Random Uppercase Hex String Generator
function generateRandomHexString(length) {
    let result = '';
    const characters = '0123456789ABCDEF';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

// Cloudflare Worker event listener
addEventListener('fetch', event => {
    event.respondWith(handleMainRequest(event.request));
});

async function handleMainRequest(request) {
    const config = {
        apiBaseUrl: 'https://api.yingmaox.cc:8700/netbarcloud/vpn',
        key1Text: 'M8T74hb17KR183b6',
        iv1Text: '242itTn000C480h1',
        key2Text: 'rwb6c4e7fz$6el%0',
        iv2Text: 'z1b6c3t4e5f6k7w8',
        userAgent: 'Octopus_Android'
    };

    try {
        const randomIosDevice = generateRandomHexString(32);

        const appRegisterPayload = JSON.stringify({
            password: "123456",
            iosDevice: randomIosDevice,
            from: "6",
            checkPassword: "123456",
            clientIp: "192.168.1.1",
            invitationCode: "6789"
        });

        const encryptedDataAppRegister = await aesCbcEncrypt(config.key1Text, config.iv1Text, appRegisterPayload);

        const appRegisterUrl = new URL(`${config.apiBaseUrl}/appRegister2`);
        appRegisterUrl.searchParams.append('data', encryptedDataAppRegister);

        const appRegisterResponse = await fetch(appRegisterUrl.toString(), {
            method: 'POST',
            headers: { 'User-Agent': config.userAgent }
        });

        if (!appRegisterResponse.ok) {
            const errorText = await appRegisterResponse.text();
            throw new Error(`appRegister2 API Error (${appRegisterResponse.status}): ${errorText}`);
        }
        const appRegisterJson = await appRegisterResponse.json();
        if (!appRegisterJson.data || !appRegisterJson.data.phoneNumber) {
            throw new Error(`appRegister2 Error: phoneNumber not found. Response: ${JSON.stringify(appRegisterJson)}`);
        }
        const phoneNumber = appRegisterJson.data.phoneNumber;

        const encryptedPhoneNumber = await aesCbcEncrypt(config.key2Text, config.iv2Text, phoneNumber);

        const phLoginUrl = new URL(`${config.apiBaseUrl}/phLogin.do`);
        phLoginUrl.searchParams.append('phoneNumber', encryptedPhoneNumber);
        phLoginUrl.searchParams.append('password', '255A42F2A6863798DBB392033F9D2FD7');
        phLoginUrl.searchParams.append('osType', 'android');

        const phLoginResponse = await fetch(phLoginUrl.toString(), {
            method: 'POST',
            headers: { 'User-Agent': config.userAgent }
        });

        if (!phLoginResponse.ok) {
            const errorText = await phLoginResponse.text();
            throw new Error(`phLogin API Error (${phLoginResponse.status}): ${errorText}`);
        }
        const phLoginJson = await phLoginResponse.json();
        if (!phLoginJson.data || !phLoginJson.data.phToken || !phLoginJson.data.vpnToken) {
            throw new Error(`phLogin Error: Token(s) not found. Response: ${JSON.stringify(phLoginJson)}`);
        }
        const { phToken, vpnToken: token } = phLoginJson.data;

        const airportNodeUrl = new URL(`${config.apiBaseUrl}/airportNode.do`);
        airportNodeUrl.searchParams.append('phToken', phToken);
        airportNodeUrl.searchParams.append('phoneNumber', phoneNumber);

        const airportNodeResponse = await fetch(airportNodeUrl.toString(), {
            method: 'POST',
            headers: {
                'User-Agent': config.userAgent,
                'token': token
            }
        });

        if (!airportNodeResponse.ok) {
            const errorText = await airportNodeResponse.text();
            throw new Error(`airportNode API Error (${airportNodeResponse.status}): ${errorText}`);
        }
        const airportNodeJson = await airportNodeResponse.json();
        if (airportNodeJson.data === null || airportNodeJson.data === undefined) { // Check for null or undefined explicitly
            throw new Error(`airportNode Error: Subscription URL (data) is null or undefined. Response: ${JSON.stringify(airportNodeJson)}`);
        }
        const subscriptionUrl = airportNodeJson.data;
        
        if (typeof subscriptionUrl !== 'string') {
             throw new Error(`airportNode Error: Subscription URL is not a string. Received: ${JSON.stringify(subscriptionUrl)}`);
        }


        return new Response(subscriptionUrl, {
            status: 200,
            headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
        });

    } catch (error) {
        console.error("Worker execution error:", error.stack);
        return new Response(error.message || 'An unexpected error occurred in the worker.', {
            status: 500,
            headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
        });
    }
}
