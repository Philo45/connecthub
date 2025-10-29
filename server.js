// --- server.js (Production Ready with Group Chat & File Upload) ---

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const fs = require('fs'); // NEW: For file system operations
const multer = require('multer'); // NEW: For handling multipart/form-data
const db = require('./db');
require('dotenv').config();

// --- Import Database Functions (UPDATED) ---
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
    getAIChatHistory
} = require('./db');

// --- Configuration Constants ---
const APP_URL = process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
const app = express();
const server = http.createServer(app);

// Use a CORS configuration for production Socket.IO setup
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});
const PORT = process.env.PORT || 3000;
const saltRounds = 10;

// --- Nodemailer Configuration ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    },
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

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'Email is required.' });

    try {
        const user = await findUserByEmail(email);

        // CRITICAL SECURITY: Always respond with a generic success message
        if (!user) {
            return res.json({ success: true, message: 'If an account is associated with that email, a password reset link has been sent.' });
        }

        const token = crypto.randomBytes(20).toString('hex');
        const expires = new Date(Date.now() + 3600000); // 1 hour expiration

        const affectedRows = await setResetToken(email, token, expires);

        if (affectedRows > 0) {
            const resetUrl = `${APP_URL}/reset-password?token=${token}`;

            const mailOptions = {
                to: email,
                from: process.env.EMAIL_USER,
                subject: 'ConnectHub Password Reset',
                text: `You are receiving this because you requested a password reset.\n\n`
                    + `Click this link to complete the reset:\n`
                    + `${resetUrl}\n\n`
                    + `This link will expire in one hour. If you did not request this, please ignore this email.`
            };

            await transporter.sendMail(mailOptions);
        }

        res.json({ success: true, message: 'If an account is associated with that email, a password reset link has been sent.' });

    } catch (error) {
        console.error('Server error during POST /forgot-password:', error.message);
        if (error.code === 'EENVELOPE') {
            return res.status(500).json({ success: false, message: 'Failed to send email. Check Nodemailer configuration.' });
        }
        res.status(500).json({ success: false, message: 'Server error during password reset request.' });
    }
});

app.get('/reset-password', async (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(400).send('Invalid request: Token is missing.');

    try {
        const user = await findUserByResetToken(token);
        if (!user) {
            return res.status(400).send('Password reset token is invalid or has expired. Please request a new one.');
        }
        res.sendFile(path.join(__dirname, 'reset_form.html'));
    } catch (error) {
        console.error('Server error during GET /reset-password:', error.message);
        res.status(500).send('A server error occurred during token verification.');
    }
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ success: false, message: 'Token and new password are required.' });

    try {
        const user = await findUserByResetToken(token);
        if (!user) return res.status(400).json({ success: false, message: 'Password reset token is invalid or has expired.' });

        const newHashedPassword = await bcrypt.hash(newPassword, saltRounds);
        await resetPassword(user.user_id, newHashedPassword);

        res.json({ success: true, message: 'Password has been successfully reset. You can now log in.' });

    } catch (error) {
        console.error('Server error during POST /reset-password:', error.message);
        res.status(500).json({ success: false, message: 'Server error during password update.' });
    }
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

// POST to save AI chat message exchange (user message + AI response)
app.post('/api/ai-chat/message', async (req, res) => {
    const { username, userMessage, aiResponse } = req.body;

    if (!username || !userMessage || !aiResponse) {
        return res.status(400).json({ success: false, message: 'Missing required chat fields.' });
    }

    try {
        const user = await findUserByUsername(username);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        const userId = user.user_id;

        // Save User Message
        await saveAIChatMessage(userId, 'user', userMessage);

        // Save AI Response
        await saveAIChatMessage(userId, 'model', aiResponse);

        res.json({ success: true, message: 'Chat exchange saved.' });
    } catch (error) {
        console.error('Error saving AI chat message exchange:', error);
        res.status(500).json({ success: false, message: 'Failed to save chat exchange.' });
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
    console.log(`Server running on ${APP_URL}`);
});