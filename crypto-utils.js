// crypto-utils.js

// Generate RSA-OAEP Key Pair for encrypting/decrypting symmetric keys
export async function generateKeyPair() {
    return await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true, // extractable
        ["encrypt", "decrypt"]
    );
}

// Generate a random AES-GCM key for encrypting messages
export async function generateSymKey() {
    return await window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
}

// Export a key to a format suitable for transmission (JWK)
export async function exportKey(key) {
    return await window.crypto.subtle.exportKey("jwk", key);
}

// Import a key from JWK format
export async function importKey(jwk, type = "public") {
    return await window.crypto.subtle.importKey(
        "jwk",
        jwk,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true,
        [type === "public" ? "encrypt" : "decrypt"]
    );
}

// Encrypt message text with AES-GCM
export async function encryptMessage(text, symKey) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
    
    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        symKey,
        data
    );

    return {
        iv: Array.from(iv), // Convert to array for JSON serialization
        ciphertext: Array.from(new Uint8Array(ciphertext))
    };
}

// Decrypt message text with AES-GCM
export async function decryptMessage(ciphertextArray, ivArray, symKey) {
    const ciphertext = new Uint8Array(ciphertextArray);
    const iv = new Uint8Array(ivArray);
    
    try {
        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            symKey,
            ciphertext
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    } catch (e) {
        console.error("Decryption failed:", e);
        return "[Decryption Error]";
    }
}

// Encrypt the AES key with a recipient's RSA Public Key
export async function encryptSymKey(symKey, publicKey) {
    // First export the AES key to raw bytes
    const rawKey = await window.crypto.subtle.exportKey("raw", symKey);
    
    // Encrypt those bytes with RSA
    const encryptedKey = await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        publicKey,
        rawKey
    );
    
    return Array.from(new Uint8Array(encryptedKey));
}

// Decrypt the AES key with our RSA Private Key
export async function decryptSymKey(encryptedSymKeyArray, privateKey) {
    const encryptedKey = new Uint8Array(encryptedSymKeyArray);
    
    const rawKey = await window.crypto.subtle.decrypt(
        {
            name: "RSA-OAEP"
        },
        privateKey,
        encryptedKey
    );
    
    // Import the raw bytes back into an AES key object
    return await window.crypto.subtle.importKey(
        "raw",
        rawKey,
        {
            name: "AES-GCM"
        },
        true,
        ["encrypt", "decrypt"]
    );
}
