// --- / --- server.js (Production Ready with Group Chat & File Upload) ---

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const fs = require('fs');
const multer = require('multer');
const db = require('./db');
require('dotenv').config();

// NEW: Import the Google Gen AI SDK and configuration
const { GoogleGenAI } = require('@google/genai');

// --- Import Database Functions (UPDATED) ---
// ... (Your existing imports)
const {
    getPublicPosts,
    getPostById,
    findUserByUsername,
    createUser,
    createPost,
    findUserIdByUsername,
    getChatHistory,
    saveMessage,
    addLike,
    removeLike,
    addReply,
    // PASSWORD RESET FUNCTIONS
    findUserByEmail,
    setResetToken,
    findUserByResetToken,
    resetPassword,
    getAllUsers,
    // GROUP CHAT FUNCTIONS
    createGroup,
    addGroupMember,
    removeGroupMember,
    getGroupDetails,
    getUserGroupIds,
    getUserGroups,
    saveGroupMessage,
    getGroupChatHistory,
    isGroupMember,
    getGroupMembers,
    // FILE UPLOAD FUNCTION
    saveFileMetadata,
    // AI CHAT FUNCTIONS (NEW)
    saveAIChatMessage,
    getAIChatHistory,
    
} = require('./db');

// --- Configuration Constants ---
const PORT = process.env.PORT || 3000;
const APP_URL = process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
const app = express();
const server = http.createServer(app);

// Initialize Gemini AI Client
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
if (!GEMINI_API_KEY) {
    console.warn("WARNING: GEMINI_API_KEY is not set in environment variables. AI chat will fail.");
}
// Initialize the AI client using the key from environment variables
const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });


// Use a CORS configuration for production Socket.IO setup
const io = socketIo(server, {
// ... (Rest of Socket.IO config)
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const saltRounds = 10;

// ... (Nodemailer Configuration)
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465, 
    secure: true, // true for 465
    auth: {
        user: process.env.EMAIL_USER,
        // CRITICAL: Must use a Google App Password here, not a regular password
        pass: process.env.EMAIL_PASSWORD, 
    },
    // Add timeouts to prevent generic 'ETIMEDOUT' by allowing more time
    connectionTimeout: 10000, // 10 seconds
    greetingTimeout: 5000,    // 5 seconds
    // You can remove or keep the tls block, as 'secure: true' handles the security layer
    // For maximal compatibility, you can keep the tls block:
    tls: {
        rejectUnauthorized: false
    }
});
// -------------------------------------------------------------------
// --- File Upload Configuration (Multer) ---
// -------------------------------------------------------------------

const UPLOAD_DIR = path.join(__dirname, 'uploads');
// Ensure the upload directory exists
if (!fs.existsSync(UPLOAD_DIR)){
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_DIR);
    },
    filename: (req, file, cb) => {
        // Create a unique filename: originalname-timestamp.ext
        const ext = path.extname(file.originalname);
        const name = path.basename(file.originalname, ext);
        cb(null, `${name}-${Date.now()}${ext}`);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 } // Limit to 10MB
});


// --- Express Setup ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CRITICAL: Serve the main static files (HTML, CSS, client JS)
app.use(express.static(__dirname));

// NEW: Serve the uploaded files from the /uploads endpoint
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Route 1: Community Posts (Main Landing Page)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Route 2: Private Chat Page
app.get('/chat', (req, res) => {
    res.sendFile(path.join(__dirname, 'chat.html'));
});

// Route 3: Dedicated Chatbot Page (NEW)
app.get('/chatbot', (req, res) => {
    res.sendFile(path.join(__dirname, 'chatbot.html'));
});
app.get('/forgot-password.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'forgot-password.html'));
});
 // ------------------------------------------
// --- API Endpoints: AI Chat Proxy (NEW & CRITICAL) ---
// ------------------------------------------

app.post('/api/chat-proxy', async (req, res) => {
    // Client sends: { username, contents: chatHistoryInGeminiFormat }
    const { username, contents } = req.body;

    if (!GEMINI_API_KEY) {
        return res.status(503).json({ success: false, message: 'AI Service Unavailable: API Key missing on server.' });
    }

    if (!username || !contents || contents.length === 0) {
        return res.status(400).json({ success: false, message: 'Missing username or chat history.' });
    }

    try {
        const user = await findUserByUsername(username);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        // 1. Call the Gemini API with the provided history (contents)
        const response = await ai.models.generateContent({
            model: "gemini-2.5-flash", // Good default model
            contents: contents, // Pass the full history for multi-turn chat
        });

        const aiResponseText = response.text;

        // 2. Extract the user message from the *last* turn of the history
        // The last element is always the current user prompt
        const userMessagePart = contents[contents.length - 1].parts[0];
        const userMessageText = userMessagePart ? userMessagePart.text : '';

        // 3. Save the full exchange to the database using the existing functions
        if (userMessageText) {
             await saveAIChatMessage(user.user_id, 'user', userMessageText);
             await saveAIChatMessage(user.user_id, 'model', aiResponseText);
        }

        // 4. Return the AI response text to the frontend
        return res.json({
            success: true,
            text: aiResponseText,
        });

    } catch (error) {
        console.error(`Error calling Gemini API for ${username}:`, error);

        // Return a generic error to the frontend
        return res.status(500).json({
            success: false,
            message: 'Internal error while communicating with the AI service. Please try again.',
            details: error.message
        });
    }
});
// ------------------------------------------
// --- API Endpoints: File Upload (NEW) ---
// ------------------------------------------

app.post('/api/upload/file', upload.single('file'), async (req, res) => {
    // chatFile is the name of the input field in the client-side form
    const file = req.file;

    // Extract the required fields from req.body
    const { username, isGroup, recipientUsernameOrId } = req.body;

    if (!file) {
        return res.status(400).json({ success: false, message: 'No file provided.' });
    }

    if (!username || !recipientUsernameOrId || typeof isGroup !== 'string') {
        return res.status(400).json({ success: false, message: 'Missing user, recipient, or chat type data in form body.' });
    }

   try {
        // ?? FIX APPLIED: Changed to findUserByUsername to get the full object { user_id, ... }
        const uploader = await findUserByUsername(username);

        if (!uploader) {
             // This correctly returns 404 if 'guest_use' is not found
             return res.status(404).json({ success: false, message: 'Uploader user not found.' });
        }

        // This is now safe because uploader is guaranteed to be a user object.
        const uploaderId = uploader.user_id;

        let recipientId = 0; // For private chat
        let groupId = 0; // For group chat
        let chatType = 'private';

        if (isGroup === 'true') {
            groupId = parseInt(recipientUsernameOrId);
            if (isNaN(groupId)) throw new Error('Invalid Group ID');
            chatType = 'group';
        } else {
            // This function call is already correct and expects a full user object
            const recipientUser = await findUserByUsername(recipientUsernameOrId);
            if (!recipientUser) throw new Error('Recipient user not found');
            recipientId = recipientUser.user_id;
        }

        // 1. Save file metadata to the database
        const fileMetadata = {
            uploaderId: uploaderId,
            originalFilename: file.originalname,
            mimeType: file.mimetype,
            storagePath: path.basename(file.path), // Only save the unique filename
            fileSizeBytes: file.size,
            groupId: groupId,
            recipientId: recipientId
        };

        // This function saves the file record and returns its ID
        const fileId = await saveFileMetadata(fileMetadata);

        // 2. Determine the message content (a link/reference to the file)
        const fileUrl = `/uploads/${path.basename(file.path)}`;
        // Format the message content as a markdown link for the client to parse
        const messageContent = `[FILE: ${file.originalname} (${(file.size / 1024).toFixed(2)} KB)](${fileUrl})`;

        // 3. Save the message (containing the file reference) to chat history
        let messageId;
        if (chatType === 'group') {
            // Security Check: Ensure uploader is a group member before saving
            const isMember = await isGroupMember(groupId, uploaderId);
            if (!isMember) throw new Error('Uploader is not a member of the group.');
            messageId = await saveGroupMessage(groupId, uploaderId, messageContent);
        } else {
            messageId = await saveMessage(uploaderId, recipientId, messageContent);
        }

        // 4. Prepare the message payload for Socket.IO
        const messageData = {
            id: messageId,
            sender: username,
            recipient: chatType === 'private' ? recipientUsernameOrId : undefined,
            groupId: chatType === 'group' ? groupId : undefined,
            content: messageContent, // The markdown link
            fileUrl: fileUrl, // Direct URL for immediate client access
            fileName: file.originalname,
            timestamp: new Date().toISOString()
        };

        // 5. Emit the message
        if (chatType === 'group') {
            io.to(`group-${groupId}`).emit('group:new_message', messageData);
        } else {
            // Private chat: emit to both sender and recipient(s)
            const recipientSocketId = onlineUsers[recipientUsernameOrId];
            if (recipientSocketId) {
                io.to(recipientSocketId).emit('chat:new_message', messageData);
            }
            // Emit back to sender (for real-time update in their own chat window)
            io.to(onlineUsers[username]).emit('chat:new_message', messageData);
        }

        // Return the messageData to the client so it can update its optimistic UI or confirm
        res.json({ success: true, message: 'File uploaded and chat message sent.', fileId, messageData });

    } catch (error) {
        console.error('Server error during POST /api/upload/file:', error.message);
        // Clean up the file if an error occurred after upload
        if (file && file.path) {
              fs.unlink(file.path, (err) => {
                  if (err) console.error('Error deleting file after DB error:', err);
              });
        }
        res.status(500).json({ success: false, message: `Internal server error: ${error.message}` });
    }
});


// ------------------------------------------
// --- API Endpoints: Password Reset ---
// ------------------------------------------

// 🟢 NEW ROUTE: Handle Forgot Password Request
app.post('/api/forgot-password', async (req, res) => {
    const { identifier } = req.body; // Can be username or email

    if (!identifier) {
        return res.status(400).json({ success: false, message: 'Username or email is required.' });
    }

    try {
        let user;
        // Check if identifier is an email (basic check)
        if (identifier.includes('@')) {
            user = await findUserByEmail(identifier);
        } else {
            user = await findUserByUsername(identifier);
        }

        // IMPORTANT: For security, always send a generic success message
        if (!user) {
            return res.json({ success: true, message: 'If an account exists, a password reset link has been sent to the associated email.' });
        }

        // Generate a reset token and set an expiry time
        const resetToken = crypto.randomBytes(32).toString('hex');
        await setResetToken(user.user_id, resetToken);

        const resetLink = `${CLIENT_URL}/reset_form.html?token=${resetToken}`;

        // Send email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'ConnectHub Password Reset',
            html: `
                <p>You requested a password reset for your ConnectHub account.</p>
                <p>Click <a href="${resetLink}">this link</a> to reset your password. This link will expire in 1 hour.</p>
                <p>If you did not request this, please ignore this email.</p>
            `
        };

        await transporter.sendMail(mailOptions);

        res.json({ success: true, message: 'If an account exists, a password reset link has been sent to the associated email.' });

    } catch (error) {
        console.error('Forgot password error:', error.message);
        res.status(500).json({ success: false, message: 'Error processing reset request.' });
    }
});

// Route for the actual password reset form (must be served by index.html or a separate page)
app.get('/reset_form', (req, res) => {
    // This assumes your frontend (index.html) handles this route and reads the token from the query params
    res.sendFile(path.join(__dirname, 'index.html'));
});


// ------------------------------------------
// --- API Endpoints: AI Chat History (NEW) ---
// ------------------------------------------

// GET AI Chat History
app.get('/api/ai-chat/history', async (req, res) => {
    const username = req.query.username;
    if (!username) {
        return res.status(401).json({ success: false, message: 'Authentication required.' });
    }
    try {
        const user = await findUserByUsername(username);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        // Fetch history in the format required by the Gemini API
        const history = await getAIChatHistory(user.user_id);

        res.json({ success: true, history });
    } catch (error) {
        console.error('Error fetching AI chat history:', error);
        res.status(500).json({ success: false, message: 'Failed to load chat history.' });
    }
});

// NEW: Secure Proxy Endpoint for AI Chat Interaction
app.post('/api/ai-chat/send', async (req, res) => {
    const { username, prompt } = req.body;

    // 1. Validation and User Lookup
    if (!username || !prompt) {
        return res.status(400).json({ success: false, message: 'Username and prompt are required.' });
    }

    // CRITICAL SECURITY: The API Key must be read from environment variables (e.env file).
    const API_KEY = process.env.GEMINI_API_KEY;
    if (!API_KEY) {
        console.error('AI service misconfigured. GEMINI_API_KEY missing from environment.');
        return res.status(500).json({ success: false, message: 'AI service misconfigured. API Key missing.' });
    }
    const API_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${API_KEY}`;

    try {
        const user = await findUserByUsername(username);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        const userId = user.user_id;

        // 2. Load Existing History
        // History is fetched in Gemini format: {role: 'user/model', parts: [{text: '...'}]}
        const chatHistory = await getAIChatHistory(userId);

        // 3. Prepare Full History for Gemini API
        // Add the *current* user message to the history list for the API call
        const currentUserMessage = { role: 'user', parts: [{ text: prompt }] };
        const geminiHistory = [...chatHistory, currentUserMessage];

        // 4. Call Gemini API (using global fetch)
        const apiResponse = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: geminiHistory,
            }),
        });

        if (!apiResponse.ok) {
            const errorText = await apiResponse.text();
            throw new Error(`External AI API failed: ${apiResponse.status} - ${errorText}`);
        }

        const data = await apiResponse.json();
        const aiResponseContent = data.candidates?.[0]?.content?.parts?.[0]?.text;

        if (!aiResponseContent) {
            throw new Error('AI response was empty or malformed.');
        }

        // 5. Save the full exchange to the database
        // Save User Message
        await saveAIChatMessage(userId, 'user', prompt);
        // Save AI Response
        await saveAIChatMessage(userId, 'model', aiResponseContent);

        // 6. Success Response: Send only the AI response back to the client
        res.json({ success: true, aiResponse: aiResponseContent, message: 'AI response generated and history saved.' });

    } catch (error) {
        console.error('Error in POST /api/ai-chat/send:', error.message);
        // Ensure the error message is safe for client consumption
        res.status(500).json({ success: false, message: 'Failed to communicate with AI service. Please try again later.' });
    }
});

// ------------------------------------------
// --- API Endpoints: Group Chat (UPDATED) ---
// ------------------------------------------

// 1. POST /api/groups: Create a new group
app.post('/api/groups', async (req, res) => {
    // Client now sends: groupName, creatorUsername, invitedUsernames (array of strings)
    const { groupName, creatorUsername, invitedUsernames } = req.body;

    // 1. Basic validation
    if (!groupName || !creatorUsername) {
        return res.status(400).json({ success: false, message: 'Group name and creator are required.' });
    }

    try {
        // 2. Resolve creator's username to ID
        const creatorId = await db.findUserIdByUsername(creatorUsername);
        if (!creatorId) {
            return res.status(404).json({ success: false, message: `Creator user (${creatorUsername}) not found.` });
        }

        // 3. Create the group in the database
        const groupId = await db.createGroup(groupName, creatorId);
        await db.addGroupMember(groupId, creatorId);
        
        // 4. Handle member invitations
        if (Array.isArray(invitedUsernames) && invitedUsernames.length > 0) {

            // Map all provided usernames (including creator) to their user IDs
            const memberIdPromises = invitedUsernames.map(async (username) => {
                const id = await db.findUserIdByUsername(username);
                return { username, id };
            });

            let membersData = await Promise.all(memberIdPromises);

            // Filter out users who don't exist (id === null)
            const validMembers = membersData.filter(member => member.id !== null);

            // Add all valid members to the group
            const addMemberPromises = validMembers.map(member =>
                db.addGroupMember(groupId, member.id)
            );
            await Promise.all(addMemberPromises);

            // Notify clients of the new group
            validMembers.forEach(member => {
                // Emit an event to tell users to refresh their groups list
                io.emit('groups:new_group_created', {
                    groupId: groupId,
                    groupName: groupName,
                    memberUsername: member.username
                });
            });
        }

        // 5. Success response (201 Created)
        res.status(201).json({ success: true, groupId: groupId, groupName: groupName, message: 'Group created successfully.' });

    } catch (error) {
        console.error('Server error creating group:', error);
        res.status(500).json({ success: false, message: 'Internal server error while creating group.' });
    }
});

// 2. POST /api/groups/add-members: Add new users to an existing group
app.post('/api/groups/add-members', async (req, res) => {
    // Client sends: { groupId, adminUsername, newMemberUsernames }
    const { groupId, adminUsername, newMemberUsernames } = req.body;
    const intGroupId = parseInt(groupId);

    // 1. Basic Validation
    if (isNaN(intGroupId) || !adminUsername || !Array.isArray(newMemberUsernames) || newMemberUsernames.length === 0) {
        return res.status(400).json({ success: false, message: 'Invalid group ID, admin, or new members list.' });
    }

    try {
        // 2. Authorization and ID Lookup
        const adminUser = await findUserByUsername(adminUsername);
        if (!adminUser) {
            return res.status(404).json({ success: false, message: `Admin user (${adminUsername}) not found.` });
        }

        // IMPORTANT SECURITY CHECK: Ensure the user attempting to add members is a current member (or admin).
        const isAdminMember = await isGroupMember(intGroupId, adminUser.user_id);
        if (!isAdminMember) {
            return res.status(403).json({ success: false, message: 'Authorization denied. You are not a member of this group.' });
        }

        // 3. Resolve usernames to IDs and filter out existing members
        const memberIdPromises = newMemberUsernames.map(async (username) => {
            const id = await findUserIdByUsername(username);
            const alreadyMember = id ? await isGroupMember(intGroupId, id) : true;
            return { username, id, alreadyMember };
        });

        const membersData = await Promise.all(memberIdPromises);

        const validNewMembers = membersData.filter(member => member.id !== null && !member.alreadyMember);

        if (validNewMembers.length === 0) {
            return res.status(409).json({ success: false, message: 'All provided users are either invalid or already members.' });
        }

        // 4. Update the Database
        const addMemberPromises = validNewMembers.map(member =>
            addGroupMember(intGroupId, member.id)
        );
        await Promise.all(addMemberPromises);

        // 5. Success and Socket.IO Notification
        const groupDetails = await getGroupDetails(intGroupId); // Fetch group details for accurate name

        // Notify each new member individually to refresh their group list
        validNewMembers.forEach(member => {
            io.to(member.username).emit('groups:new_group_created', {
                groupId: intGroupId,
                groupName: groupDetails ? groupDetails.group_name : `Group ${intGroupId}`,
                message: `You were added to Group ${intGroupId}`
            });
        });

        // Notify all current group members (via the group room) to refresh the member count/list
        io.to(`group-${intGroupId}`).emit('groups:member_added', {
            groupId: intGroupId,
            newMembers: validNewMembers.map(m => m.username)
        });

        return res.json({
            success: true,
            message: `${validNewMembers.length} member(s) successfully added to the group.`,
            addedMembers: validNewMembers.map(m => m.username)
        });

    } catch (error) {
        console.error("Server error adding group members:", error);
        return res.status(500).json({ success: false, message: 'Internal server error while adding group members.' });
    }
});

// 3. POST /api/groups/remove-member: Remove a user from a group
app.post('/api/groups/remove-member', async (req, res) => {
    const { groupId, adminUsername, userToRemoveUsername } = req.body;
    const intGroupId = parseInt(groupId);

    if (isNaN(intGroupId) || !adminUsername || !userToRemoveUsername) {
        return res.status(400).json({ success: false, message: 'Invalid data provided.' });
    }

    try {
        // 1. Resolve IDs
        const adminUser = await findUserByUsername(adminUsername);
        const userToRemove = await findUserByUsername(userToRemoveUsername);

        if (!adminUser || !userToRemove) {
            return res.status(404).json({ success: false, message: 'Admin or user to remove not found.' });
        }

        // 2. Authorization Check: Admin must be a member
        const isAdminMember = await isGroupMember(intGroupId, adminUser.user_id);
        if (!isAdminMember) {
            return res.status(403).json({ success: false, message: 'Authorization denied. You are not a member of this group.' });
        }

        // 3. Perform removal
        const affectedRows = await removeGroupMember(intGroupId, userToRemove.user_id);

        if (affectedRows > 0) {
            // 4. Socket.IO Notification: Notify the removed user and the group
            io.to(userToRemove.username).emit('groups:member_removed', {
                groupId: intGroupId,
                message: `You were removed from Group ${intGroupId}`
            });

            // Note: The removed user must leave the socket.io room. This is typically handled on the client side upon receiving 'groups:member_removed'.
            io.to(`group-${intGroupId}`).emit('groups:member_list_update', {
                groupId: intGroupId,
                removedMember: userToRemoveUsername
            });

            return res.json({ success: true, message: `${userToRemoveUsername} removed from the group.` });
        } else {
            return res.status(404).json({ success: false, message: 'User was not a member of this group or group does not exist.' });
        }

    } catch (error) {
        console.error('Server error removing group member:', error);
        return res.status(500).json({ success: false, message: 'Internal server error while removing member.' });
    }
});

// 4. GET /api/groups: Fetch all groups a user belongs to
app.get('/api/groups', async (req, res) => {
    const { username } = req.query;

    if (!username) {
        return res.status(400).json({ success: false, message: 'Username is required.' });
    }

    try {
        const user = await findUserByUsername(username);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const groups = await getUserGroups(user.user_id);

        // Return groups wrapped in an object for the client
        res.json({ success: true, groups: groups });

    } catch (error) {
        console.error('Server error during GET /api/groups:', error.message);
        res.status(500).json({ success: false, groups: [] }); // Return empty array within object on error
    }
});

// 5. GET /api/groups/:groupId: Fetch details for a specific group
app.get('/api/groups/:groupId', async (req, res) => {
    const groupId = parseInt(req.params.groupId);
    const { username } = req.query;

    if (isNaN(groupId) || !username) {
        return res.status(400).json({ success: false, message: 'Invalid Group ID or username.' });
    }

    try {
        const user = await findUserByUsername(username);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        // Security check: Ensure the user is a member of the group
        const isMember = await isGroupMember(groupId, user.user_id);
        if (!isMember) {
            return res.status(403).json({ success: false, message: 'Authorization denied. You are not a member of this group.' });
        }

        const groupDetails = await getGroupDetails(groupId);

        if (!groupDetails) {
            return res.status(404).json({ success: false, message: 'Group not found.' });
        }

        const members = await getGroupMembers(groupId);

        res.json({
            success: true,
            group: {
                ...groupDetails,
                members: members
            }
        });

    } catch (error) {
        console.error('Server error during GET /api/groups/:groupId:', error.message);
        res.status(500).json({ success: false, message: 'Internal server error fetching group details.' });
    }
});

// 6. GET /api/messages/group/:groupId: Fetch group chat history
app.get('/api/messages/group/:groupId', async (req, res) => {
    const groupId = parseInt(req.params.groupId);
    const { username } = req.query;

    if (isNaN(groupId) || !username) {
        return res.status(400).json([]); // Return empty array for client on error
    }

    try {
        const user = await findUserByUsername(username);
        if (!user) return res.status(404).json([]);

        // Security check: Ensure the user is a member of the group
        const isMember = await isGroupMember(groupId, user.user_id);
        if (!isMember) {
            return res.status(403).json([]);
        }

        const messages = await getGroupChatHistory(groupId);
        // The client expects the array of messages directly
        res.json(messages);

    } catch (error) {
        console.error('Server error during GET /api/messages/group:', error.message);
        res.status(500).json([]);
    }
});


// ------------------------------------------
// --- API Endpoints: Community/Auth/DM (Existing & Updated) ---
// ------------------------------------------

// GET /posts - Fetch public community posts (Feed)
app.get('/posts', async (req, res) => {
    const { username } = req.query;
    let currentUserId = 0;

    try {
        if (username) {
            const user = await findUserByUsername(username);
            if (user) currentUserId = user.user_id;
        }
        const posts = await getPublicPosts(currentUserId);
        res.json({ success: true, posts });
    } catch (error) {
        console.error('API Error in GET /posts:', error.message);
        res.status(500).json({ success: false, message: 'Failed to fetch posts.' });
    }
});

// GET /posts/:id - Fetch a single public community post
app.get('/posts/:id', async (req, res) => {
    const postId = parseInt(req.params.id);
    const { username } = req.query; // Used to check if the current user liked it

    if (isNaN(postId)) return res.status(400).json({ success: false, message: 'Invalid Post ID.' });

    let currentUserId = 0;

    try {
        if (username) {
            const user = await findUserByUsername(username);
            if (user) currentUserId = user.user_id;
        }

        const post = await getPostById(postId, currentUserId);

        if (!post) {
            return res.status(404).json({ success: false, message: 'Post not found.' });
        }

        res.json({ success: true, post });

    } catch (error) {
        console.error('API Error in GET /posts/:id:', error.message);
        res.status(500).json({ success: false, message: 'Failed to fetch single post.' });
    }
});

// POST /posts - Create a new community post
app.post('/posts', async (req, res) => {
    const { author, content } = req.body;
    if (!author || !content) return res.status(400).json({ success: false, message: 'Author and content are required.' });

    try {
        const user = await findUserByUsername(author);
        if (!user || !user.user_id) return res.status(401).json({ success: false, message: 'User not authenticated or found.' });

        const newPostId = await createPost(user.user_id, content);
        io.emit('community:new_post', { postId: newPostId, author, content, timestamp: new Date() });

        res.status(201).json({ success: true, message: 'Post created successfully.' });
    } catch (error) {
        console.error('Server error during POST /posts:', error.message);
        res.status(500).json({ success: false, message: 'Failed to create post.' });
    }
});

app.post('/api/posts/:id/like', async (req, res) => {
    const postId = parseInt(req.params.id);
    const { username } = req.body;

    if (isNaN(postId) || !username) return res.status(400).json({ success: false, message: 'Invalid Post ID or username.' });

    try {
        const user = await findUserByUsername(username);
        if (!user || !user.user_id) return res.status(404).json({ success: false, message: 'User not found.' });
        const userId = user.user_id;

        let action;
        let affectedRows = await removeLike(postId, userId);

        if (affectedRows > 0) {
            action = 'unliked';
        } else {
            const result = await addLike(postId, userId);
            if (result) {
                action = 'liked';
            } else {
                return res.status(500).json({ success: false, message: 'Failed to toggle like status.' });
            }
        }

        io.emit('community:like_update', { postId, action, username });
        res.json({ success: true, message: `Post ${action}!`, action });

    } catch (error) {
        console.error('Server error during POST /api/posts/like:', error.message);
        res.status(500).json({ success: false, message: 'Failed to process like.' });
    }
});

app.post('/api/posts/:id/reply', async (req, res) => {
    const postId = parseInt(req.params.id);
    const { username, content } = req.body;

    if (isNaN(postId) || !username || !content) return res.status(400).json({ success: false, message: 'Invalid Post ID, username, or content.' });

    try {
        const user = await findUserByUsername(username);
        if (!user || !user.user_id) return res.status(404).json({ success: false, message: 'User not found.' });
        const authorId = user.user_id;

        const replyId = await addReply(postId, authorId, content);
        io.emit('community:reply_added', { postId, replyId, author: username, content, created_at: new Date() });

        res.status(201).json({ success: true, message: 'Reply added successfully.' });

    } catch (error) {
        console.error('Server error during POST /api/posts/reply:', error.message);
        res.status(500).json({ success: false, message: 'Failed to add reply.' });
    }
});


// -------------------------------------------------------------------
// --- NEW: Virtual Assistant Concern Submission API (Corrected) ---
// -------------------------------------------------------------------
app.post('/api/submit-concern', async (req, res) => {
    const { username, email, concern } = req.body;
    const targetEmail = 'oyoookoth42@gmail.com'; // Hardcoded target email

    if (!username || !email || !concern) {
        return res.status(400).json({ success: false, message: 'Missing username, email, or concern.' });
    }

    try {
        // --- Find User ID and Save to DB ---
        // Find the user object to get the ID, or use null if the user is not found (meaning not logged in/signed up)
        const user = await findUserByUsername(username);
        // Assuming findUserByUsername returns an object with user_id
        const userId = user ? user.user_id : null;

        // Save the ticket to the database (Requires implementation in db.js)
        // This function is now correctly imported at the top of the file.
       const ticketId = await db.saveSupportTicket(userId, username, email, concern);
        console.log(`Saved support ticket ID: ${ticketId}`);
        // -----------------------------------

        const mailOptions = {
            to: targetEmail,
            from: process.env.EMAIL_USER,
            subject: `ConnectHub Assistant Concern (Ticket ID: ${ticketId}) from ${username}`,
            html: `
                <p>A new concern has been submitted through the Virtual Assistant:</p>
                <hr>
                <p><strong>Ticket ID:</strong> ${ticketId}</p>
                <p><strong>Username:</strong> ${username}</p>
                <p><strong>User Email:</strong> ${email}</p>
                <p><strong>Concern:</strong></p>
                <div style="border: 1px solid #ccc; padding: 10px; margin-top: 10px; background-color: #f9f9f9;">
                    <p>${concern.replace(/\n/g, '<br>')}</p>
                </div>
                <hr>
                <p>Please respond to the user at ${email}.</p>
            `,
        };

        // This is the server-side action to send the email
        await transporter.sendMail(mailOptions);

        console.log(`Successfully sent concern email from ${username} to ${targetEmail}`);
        res.json({ success: true, message: 'Concern submitted and email sent successfully.' });
    } catch (error) {
        console.error('Email/DB saving error for virtual assistant:', error);
        
        // **CRITICAL FIX/IMPROVEMENT: Check for common email-related errors**
        if (error.code === 'EAUTH' || error.code === 'EENVELOPE') {
             // EAUTH is an authentication error (bad user/pass for Nodemailer)
             // EENVELOPE is often a configuration/syntax error in the mail options
             console.error(`Nodemailer error code: ${error.code}. Check EMAIL_USER and EMAIL_PASSWORD in .env and transporter config.`);
        }

        res.status(500).json({ success: false, message: 'Internal server error. Could not complete submission.' });
    }
});

app.post('/signup', async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password || !email) return res.status(400).json({ success: false, message: 'Username, password, and email are required.' });

    try {
        const existingUser = await findUserByUsername(username);
        if (existingUser) return res.status(409).json({ success: false, message: 'Username already taken.' });

        const hashedPassword = await bcrypt.hash(password, saltRounds);
        await createUser(username, hashedPassword, email);

        return res.json({ success: true, message: 'Registration successful!', username: username });

    } catch (error) {
        console.error('Server error during signup:', error.message);
        res.status(500).json({ success: false, message: 'An unexpected error occurred during registration.' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: 'Username and password are required.' });

    try {
        const user = await findUserByUsername(username);
        if (!user) return res.status(401).json({ success: false, message: 'Invalid username or password.' });

        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (passwordMatch) {
            return res.json({ success: true, message: 'Login successful!', username: user.username, });
        } else {
            return res.status(401).json({ success: false, message: 'Invalid username or password.' });
        }

    } catch (error) {
        console.error('Server error during login:', error.message);
        res.status(500).json({ success: false, message: 'An unexpected error occurred.' });
    }
});

// GET /api/users - Fetch all users for private chat list
app.get('/api/users', async (req, res) => {
    const { currentUsername } = req.query;

    try {
        const registeredUsers = await getAllUsers();
        // Filter out the current user and map to expected structure
        const users = registeredUsers
            .filter(u => u.username !== currentUsername)
            .map(user => ({
                user_id: user.user_id,
                username: user.username
            }));

        // The client expects an array of users directly
        res.json(users);
    } catch (error) {
        console.error('Error fetching all users:', error.message);
        res.status(500).json([]);
    }
});

app.get('/api/user/me', async (req, res) => {
    const { username } = req.query;

    if (!username) {
        return res.status(400).json({ success: false, message: 'Username is required.' });
    }

    try {
        const user = await findUserByUsername(username);

        if (user) {
            return res.json({
                success: true,
                user_id: user.user_id,
                username: user.username,
            });
        } else {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
    } catch (error) {
        console.error('Error in /api/user/me:', error);
        return res.status(500).json({ success: false, message: 'Internal Server Error: Failed to fetch user data.' });
    }
});

/// GET /api/messages/private/:recipientUsername

app.get('/api/messages/private/:recipientUsername', async (req, res) => {
    const recipient = req.params.recipientUsername;
    const { username: sender } = req.query;

    if (!recipient || !sender) return res.status(400).json([]);

    try {
    // 1. Resolve usernames to IDs (assuming findUserIdByUsername is defined)
    const senderId = await findUserIdByUsername(sender);
    const recipientId = await findUserIdByUsername(recipient);

    if (!senderId || !recipientId) return res.status(404).json([]);

    // 2. Call the chat history function
    const messages = await getChatHistory(senderId, recipientId);

    // 3. Success: Return the messages array
    return res.json(messages);

} catch (error) {
        console.error('Server error during GET /api/messages/private:', error.message);
        // CRITICAL: Return a 500 status with an empty array or an error message in JSON
        return res.status(500).json({ error: 'Failed to fetch messages due to server error.' });
    }
});

// POST /api/messages/read/:recipientUsername - Mark private messages as read
app.post('/api/messages/read/:recipientUsername', async (req, res) => {
    // This is a placeholder for the backend to update a 'read' status on private_messages.
    // For this setup, we just return success to satisfy the client's API call.
    res.json({ success: true, message: 'Read status updated.' });
});

// ------------------------------------------
// --- Socket.io Logic (UPDATED for Group Rooms) ---
// ------------------------------------------

// Map: { username: socket.id }
let onlineUsers = {};

io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);

    // --- Private Chat / Presence & Group Room Joining ---
    socket.on('user:set_online', async (username) => {
        if (!username) return;

        // Disconnect existing socket if user is already logged in elsewhere
        if (onlineUsers[username] && onlineUsers[username] !== socket.id) {
            const oldSocket = io.sockets.sockets.get(onlineUsers[username]);
            if(oldSocket) {
                console.log(`Force disconnecting old socket for user ${username}: ${oldSocket.id}`);
                // oldSocket.disconnect(true); // Can uncomment this if you want to enforce one session per user
            }
        }

        onlineUsers[username] = socket.id;
        socket.username = username; // Store username on the socket object

        // --- NEW: Group Room Joining ---
        try {
            const user = await findUserByUsername(username);
            if (user) {
                const groupIds = await getUserGroupIds(user.user_id);

                groupIds.forEach(groupId => {
                    const roomName = `group-${groupId}`;
                    socket.join(roomName);
                    console.log(`User ${username} joined room: ${roomName}`);
                });
            }
        } catch (error) {
            console.error(`Error joining group rooms for ${username}:`, error.message);
        }
        // --- END NEW LOGIC ---

        console.log(`User ${username} is now online.`);
        // CRITICAL: This is where the client gets the list to show green dots.
        io.emit('users:online:list', Object.keys(onlineUsers));
    });

    // --- Private Message Sending (Replaces POST API) ---
    socket.on('chat:send_message', async (data) => {
        const { from, to, content } = data; // from: sender username, to: recipient username

        try {
            const senderId = await findUserIdByUsername(from);
            const recipientId = await findUserIdByUsername(to);

            if (!senderId || !recipientId) return;

            // 1. Save to database
            const messageId = await saveMessage(senderId, recipientId, content);

            const messageData = {
                id: messageId,
                sender: from,
                recipient: to,
                content: content,
                timestamp: new Date().toISOString()
            };

            // 2. Emit to recipient (if online)
            const recipientSocketId = onlineUsers[to];
            if (recipientSocketId) {
                io.to(recipientSocketId).emit('chat:new_message', messageData);
            }

            // 3. Emit back to sender (for real-time update in their own chat window)
            io.to(onlineUsers[from]).emit('chat:new_message', messageData);

        } catch (error) {
            console.error('Socket error during chat:send_message:', error.message);
        }
    });

    // --- Group Message Sending ---
    socket.on('group:send_message', async (data) => {
        const { from, to: groupId, content } = data; // from: sender username, to: groupId

        try {
            const sender = await findUserByUsername(from);
            const intGroupId = parseInt(groupId);

            if (!sender || isNaN(intGroupId)) return;

            // Security check: ensure sender is a member
            const isMember = await isGroupMember(intGroupId, sender.user_id);
            if (!isMember) return;

            // 1. Save message to database
            const messageId = await saveGroupMessage(intGroupId, sender.user_id, content);

            const messageData = {
                id: messageId,
                groupId: intGroupId,
                sender: from,
                content: content,
                timestamp: new Date().toISOString()
            };

            // 2. Broadcast the message to the group's Socket.IO room
            io.to(`group-${intGroupId}`).emit('group:new_message', messageData);

        } catch (error) {
            console.error('Socket error during group:send_message:', error.message);
        }
    });


    // --- Disconnection ---
    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.id}`);

        if (socket.username) {
            // Check if this socket ID is still the official one for the user
            if (onlineUsers[socket.username] === socket.id) {
                delete onlineUsers[socket.username];
                // Notify all clients of the updated online list
                io.emit('users:online:list', Object.keys(onlineUsers));
            }
        }
    });
});


// --- Start Server ---
server.listen(PORT, () => {
    console.log(`Server running on ${PORT}`);
});