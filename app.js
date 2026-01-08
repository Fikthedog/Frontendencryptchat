import * as Crypto from './crypto-utils.js';

// State
let myKeyPair = null;
let socket = null;
let myUsername = '';
let myToken = '';
let isAdmin = false;
let connectedUsers = new Map(); // socketId -> { username, publicKeyObject, isAdmin }
let isLoginMode = true;

// DOM Elements
const loginScreen = document.getElementById('login-screen');
const chatScreen = document.getElementById('chat-screen');
const usernameInput = document.getElementById('username-input');
const passwordInput = document.getElementById('password-input');
const serverUrlInput = document.getElementById('server-url-input');
const authBtn = document.getElementById('auth-btn');
const tabLogin = document.getElementById('tab-login');
const tabRegister = document.getElementById('tab-register');
const statusMsg = document.getElementById('status-msg');
const errorMsg = document.getElementById('error-msg');
const messagesContainer = document.getElementById('messages-container');
const messageForm = document.getElementById('message-form');
const messageInput = document.getElementById('message-input');
const displayUsername = document.getElementById('display-username');
const userCount = document.getElementById('user-count');
const adminBadge = document.getElementById('admin-badge');
const adminPanelBtn = document.getElementById('admin-panel-btn');
const adminModal = document.getElementById('admin-modal');
const closeAdminBtn = document.getElementById('close-admin-btn');
const refreshAdminBtn = document.getElementById('refresh-admin-btn');
const adminUserList = document.getElementById('admin-user-list');
const statTotalUsers = document.getElementById('stat-total-users');
const statOnlineUsers = document.getElementById('stat-online-users');

// Toggle Login/Register
tabLogin.addEventListener('click', () => setAuthMode(true));
tabRegister.addEventListener('click', () => setAuthMode(false));

function setAuthMode(login) {
    isLoginMode = login;
    if (login) {
        tabLogin.classList.add('text-green-500', 'border-b-2', 'border-green-500', 'font-bold');
        tabLogin.classList.remove('text-gray-400');
        tabRegister.classList.remove('text-green-500', 'border-b-2', 'border-green-500', 'font-bold');
        tabRegister.classList.add('text-gray-400');
        authBtn.innerText = "Login & Join";
    } else {
        tabRegister.classList.add('text-green-500', 'border-b-2', 'border-green-500', 'font-bold');
        tabRegister.classList.remove('text-gray-400');
        tabLogin.classList.remove('text-green-500', 'border-b-2', 'border-green-500', 'font-bold');
        tabLogin.classList.add('text-gray-400');
        authBtn.innerText = "Register & Join";
    }
}

// Helper to format time
function formatTime(isoString) {
    return new Date(isoString).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// UI: Add Message
function addMessageToUI(username, text, timestamp, isSelf, isSenderAdmin) {
    const div = document.createElement('div');
    div.className = `flex flex-col ${isSelf ? 'items-end' : 'items-start'}`;
    
    const bubble = document.createElement('div');
    bubble.className = `max-w-[80%] rounded-lg p-3 ${
        isSelf ? 'bg-green-600 text-white' : 'bg-gray-700 text-gray-200'
    }`;
    
    const meta = document.createElement('div');
    meta.className = `text-xs mb-1 flex gap-2 items-center ${isSelf ? 'text-green-200' : 'text-gray-400'}`;
    
    let adminTag = '';
    if (isSenderAdmin) {
        adminTag = `<span class="bg-red-600 text-[10px] px-1 rounded uppercase font-bold text-white">ADMIN</span>`;
    }

    meta.innerHTML = `${adminTag} ${username} • ${formatTime(timestamp)}`;
    
    const content = document.createElement('div');
    content.innerText = text;
    
    bubble.appendChild(meta);
    bubble.appendChild(content);
    div.appendChild(bubble);
    
    messagesContainer.appendChild(div);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// UI: System Message
function addSystemMessage(text) {
    const div = document.createElement('div');
    div.className = 'text-center text-xs text-gray-500 my-2';
    div.innerText = text;
    messagesContainer.appendChild(div);
}

// Auth & Join
authBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim();
    const serverUrl = serverUrlInput.value.trim();
    
    if (!username || !serverUrl || !password) {
        errorMsg.innerText = "Please fill in all fields.";
        errorMsg.classList.remove('hidden');
        return;
    }

    errorMsg.classList.add('hidden');
    statusMsg.innerText = isLoginMode ? "Logging in..." : "Registering...";
    statusMsg.classList.remove('hidden');
    authBtn.disabled = true;

    try {
        // 1. Authenticate via REST
        const endpoint = isLoginMode ? '/auth/login' : '/auth/register';
        const response = await fetch(`${serverUrl}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Authentication failed');

        myToken = data.token;
        myUsername = data.username;
        isAdmin = data.isAdmin;

        // 2. Generate Keys
        statusMsg.innerText = "Generating 2048-bit RSA keys...";
        myKeyPair = await Crypto.generateKeyPair();
        const exportedPublicKey = await Crypto.exportKey(myKeyPair.publicKey);

        // 3. Connect to Socket
        statusMsg.innerText = "Connecting to server...";
        socket = io(serverUrl, {
            auth: { token: myToken }
        });

        socket.on('connect_error', (err) => {
            console.error(err);
            statusMsg.classList.add('hidden');
            errorMsg.innerText = `Connection failed: ${err.message}`;
            errorMsg.classList.remove('hidden');
            authBtn.disabled = false;
        });

        socket.on('error', (msg) => {
            alert(msg);
            location.reload();
        });

        socket.on('connect', () => {
            statusMsg.innerText = "Connected! Joining room...";
            
            // 4. Join
            socket.emit('join', {
                publicKey: exportedPublicKey
            });
            
            displayUsername.innerText = myUsername;
            if (isAdmin) {
                adminBadge.classList.remove('hidden');
                adminPanelBtn.classList.remove('hidden');
            }
            
            // Switch UI
            loginScreen.classList.add('hidden');
            chatScreen.classList.remove('hidden');
        });

        // 5. Handle Events
        setupSocketEvents();

    } catch (err) {
        console.error(err);
        statusMsg.classList.add('hidden');
        errorMsg.innerText = `Error: ${err.message}`;
        errorMsg.classList.remove('hidden');
        authBtn.disabled = false;
    }
});

function setupSocketEvents() {
    socket.on('existing-users', async (usersList) => {
        for (const user of usersList) {
            try {
                const key = await Crypto.importKey(user.publicKey);
                connectedUsers.set(user.id, { username: user.username, publicKey: key, isAdmin: user.isAdmin });
            } catch (e) {
                console.error("Failed to import key for user", user.username, e);
            }
        }
        updateUserCount();
    });

    socket.on('user-joined', async (user) => {
        try {
            const key = await Crypto.importKey(user.publicKey);
            connectedUsers.set(user.id, { username: user.username, publicKey: key, isAdmin: user.isAdmin });
            addSystemMessage(`${user.username} joined the chat`);
            updateUserCount();
        } catch (e) {
            console.error("Failed to import key for new user", user.username, e);
        }
    });

    socket.on('user-left', (id) => {
        const user = connectedUsers.get(id);
        if (user) {
            addSystemMessage(`${user.username} left the chat`);
            connectedUsers.delete(id);
            updateUserCount();
        }
    });

    socket.on('chat-message', async (payload) => {
        const { senderId, username, timestamp, iv, ciphertext, recipientKeys, isAdmin: isSenderAdmin } = payload;
        const isSelf = senderId === socket.id;

        const myEncryptedKey = recipientKeys[socket.id];
        
        if (!myEncryptedKey) {
            console.warn("Received message but no key found for me.");
            return;
        }

        try {
            const symKey = await Crypto.decryptSymKey(myEncryptedKey, myKeyPair.privateKey);
            const text = await Crypto.decryptMessage(ciphertext, iv, symKey);
            addMessageToUI(username, text, timestamp, isSelf, isSenderAdmin);
        } catch (e) {
            console.error("Failed to decrypt message:", e);
            addSystemMessage(`Error: Could not decrypt message from ${username}`);
        }
    });

    // Admin Responses
    socket.on('admin-stats', (data) => {
        updateAdminUI(data);
    });

    socket.on('admin-response', (msg) => {
        alert(msg);
        socket.emit('admin-action', { type: 'get-stats' }); // Refresh
    });
}

function updateUserCount() {
    const count = connectedUsers.size + 1; // +1 for self
    userCount.innerText = `${count} Online`;
}

// Send Message
messageForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text) return;

    messageInput.value = '';

    try {
        const symKey = await Crypto.generateSymKey();
        const { iv, ciphertext } = await Crypto.encryptMessage(text, symKey);
        
        const recipientKeys = {};
        
        recipientKeys[socket.id] = await Crypto.encryptSymKey(symKey, myKeyPair.publicKey);
        
        for (const [id, user] of connectedUsers) {
            recipientKeys[id] = await Crypto.encryptSymKey(symKey, user.publicKey);
        }
        
        socket.emit('chat-message', {
            iv,
            ciphertext,
            recipientKeys
        });

    } catch (e) {
        console.error("Encryption failed:", e);
        alert("Failed to encrypt message.");
    }
});

// Admin Panel Logic
adminPanelBtn.addEventListener('click', () => {
    adminModal.classList.remove('hidden');
    socket.emit('admin-action', { type: 'get-stats' });
});

closeAdminBtn.addEventListener('click', () => {
    adminModal.classList.add('hidden');
});

refreshAdminBtn.addEventListener('click', () => {
    socket.emit('admin-action', { type: 'get-stats' });
});

function updateAdminUI(data) {
    statTotalUsers.innerText = data.totalRegistered;
    statOnlineUsers.innerText = data.onlineCount;

    adminUserList.innerHTML = '';
    
    // Merge online status into all users list
    const onlineMap = new Map();
    data.onlineList.forEach(u => onlineMap.set(u.username, u.id)); // socketId

    data.users.forEach(user => {
        const tr = document.createElement('tr');
        tr.className = 'border-b border-gray-700 hover:bg-gray-700 transition';
        
        const isOnline = onlineMap.has(user.username);
        const socketId = onlineMap.get(user.username);
        
        tr.innerHTML = `
            <td class="p-3 font-medium text-white">${user.username}</td>
            <td class="p-3">
                ${user.is_admin ? '<span class="text-red-400 font-bold">Admin</span>' : 'User'}
            </td>
            <td class="p-3">
                ${isOnline ? '<span class="text-green-400">Online</span>' : '<span class="text-gray-500">Offline</span>'}
                ${user.is_banned ? '<span class="text-red-600 ml-2 font-bold">BANNED</span>' : ''}
            </td>
            <td class="p-3 text-right">
                ${!user.is_admin ? `
                    ${isOnline ? `<button onclick="kickUser('${socketId}')" class="text-yellow-500 hover:text-yellow-400 text-xs mr-2">Kick</button>` : ''}
                    ${user.is_banned 
                        ? `<button onclick="unbanUser(${user.id})" class="text-green-500 hover:text-green-400 text-xs">Unban</button>`
                        : `<button onclick="banUser(${user.id})" class="text-red-500 hover:text-red-400 text-xs">Ban</button>`
                    }
                ` : ''}
            </td>
        `;
        adminUserList.appendChild(tr);
    });
}

// Expose admin functions to window for onclick handlers
window.kickUser = (socketId) => {
    if(confirm('Kick this user?')) {
        socket.emit('admin-action', { type: 'kick', targetSocketId: socketId });
    }
};

window.banUser = (userId) => {
    if(confirm('Ban this user permanently?')) {
        socket.emit('admin-action', { type: 'ban', userId });
    }
};

window.unbanUser = (userId) => {
    if(confirm('Unban this user?')) {
        socket.emit('admin-action', { type: 'unban', userId });
    }
};
