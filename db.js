// --- db.js (Database Abstraction Layer) ---

// NOTE: We must use the promise version of mysql2 and remove dotenv for cloud deployment.
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
// Removed: require('dotenv').config(); // Render handles env vars

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
    console.error("CRITICAL ERROR: DATABASE_URL environment variable is NOT set.");
    console.error("Please set the DATABASE_URL secret in your Render dashboard.");
    process.exit(1);
}

// Configuration object passed to the connection pool
const dbConfig = {
    uri: databaseUrl, // Use the full connection URI provided by Render/Railway
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 20000, // Increased timeout for cloud connection stability
    // CRITICAL: SSL configuration required for secure cloud connections (e.g., Railway)
   charset: 'utf8mb4',
    ssl: {
        rejectUnauthorized: false
    }
};

// Create the connection pool
// This pool is created with the promise API directly via the require.
const pool = mysql.createPool(dbConfig);
// --- TABLE CREATION FUNCTION (NEW) ---
async function createAIChatTable() {
    const query = `
        CREATE TABLE IF NOT EXISTS ai_chat_messages (
            message_id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            role VARCHAR(10) NOT NULL, -- 'user' or 'model'
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        );
    `;
    await pool.query(query);
    console.log("AI Chat Messages table checked/created.");
}

// Initial connection check
pool.getConnection()
    .then(async (connection) => {
        console.log('✅ Successfully connected to the database! 🚀');
        await createAIChatTable();
        connection.release();
    })
    .catch(error => {
        // This log will clearly print the exact connection error (e.g., ETIMEDOUT)
        console.error("❌ Database connection FAILED. Critical Error details:", error.message);
        console.error("ACTION REQUIRED: Check your DATABASE_URL value and ensure it is correct.");
        // Exit the application if the DB connection is essential
        process.exit(1);
    });



// --- USER & AUTHENTICATION HELPERS ---

// Find a user by username, returning full user object (used by /api/user/me)
async function findUserByUsername(username) {
    const [rows] = await pool.query('SELECT user_id, username, password_hash, email FROM users WHERE username = ?', [username]);
    return rows[0];
}

// Find user ID by username
async function findUserIdByUsername(username) {
    const [rows] = await pool.query('SELECT user_id FROM users WHERE username = ?', [username]);
    return rows[0] ? rows[0].user_id : null;
}

// Find user by email
async function findUserByEmail(email) {
    const [rows] = await pool.query('SELECT user_id, username, password_hash, email FROM users WHERE email = ?', [email]);
    return rows[0];
}

// Create a new user
async function createUser(username, hashedPassword, email) {
    const [result] = await pool.query(
        'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
        [username, hashedPassword, email]
    );
    return result.insertId;
}

// Fetch ALL registered usernames (for chat user list)
async function getAllUsers() {
    const [rows] = await pool.query('SELECT user_id, username FROM users ORDER BY username ASC');
    return rows;
}


// --- SOCIAL FEED FUNCTIONS ---

// Fetch all public posts, including like status, counts, and replies
async function getPublicPosts(currentUserId) {
    const [posts] = await pool.query(`
        SELECT
            p.post_id,
            p.content,
            p.created_at,
            u.username AS author,
            (SELECT COUNT(*) FROM likes WHERE post_id = p.post_id) AS like_count,
            (SELECT COUNT(*) FROM replies WHERE post_id = p.post_id) AS reply_count,
            (SELECT EXISTS(
                SELECT 1 FROM likes
                WHERE post_id = p.post_id AND user_id = ?
            )) AS is_liked_by_current_user
        FROM posts p
        JOIN users u ON p.user_id = u.user_id
        ORDER BY p.created_at DESC
    `, [currentUserId]);

    if (posts.length === 0) {
        return [];
    }

    const postIds = posts.map(p => p.post_id);
    const postIdsPlaceholder = postIds.map(() => '?').join(',');

    const [replies] = await pool.query(`
        SELECT
            r.post_id,
            r.content,
            r.created_at,
            u.username AS author
        FROM replies r
        JOIN users u ON r.user_id = u.user_id
        WHERE r.post_id IN (${postIdsPlaceholder})
        ORDER BY r.created_at ASC
    `, postIds);

    const repliesMap = replies.reduce((acc, reply) => {
        if (!acc[reply.post_id]) { acc[reply.post_id] = []; }
        acc[reply.post_id].push(reply);
        return acc;
    }, {});

    return posts.map(post => ({
        ...post,
        post_id: parseInt(post.post_id),
        like_count: parseInt(post.like_count),
        reply_count: parseInt(post.reply_count),
        is_liked_by_current_user: post.is_liked_by_current_user === 1,
        replies: repliesMap[post.post_id] || []
    }));
}

// Fetch a single post by ID, including like status, counts, and replies
async function getPostById(postId, currentUserId) {
    const [posts] = await pool.query(`
        SELECT
            p.post_id,
            p.content,
            p.created_at,
            u.username AS author,
            (SELECT COUNT(*) FROM likes WHERE post_id = p.post_id) AS like_count,
            (SELECT COUNT(*) FROM replies WHERE post_id = p.post_id) AS reply_count,
            (SELECT EXISTS(
                SELECT 1 FROM likes
                WHERE post_id = p.post_id AND user_id = ?
            )) AS is_liked_by_current_user
        FROM posts p
        JOIN users u ON p.user_id = u.user_id
        WHERE p.post_id = ?
    `, [currentUserId, postId]);

    const post = posts[0];
    if (!post) { return null; }

    const [replies] = await pool.query(`
        SELECT
            r.post_id,
            r.content,
            r.created_at,
            u.username AS author
        FROM replies r
        JOIN users u ON r.user_id = u.user_id
        WHERE r.post_id = ?
        ORDER BY r.created_at ASC
    `, [postId]);

    return {
        ...post,
        post_id: parseInt(post.post_id),
        like_count: parseInt(post.like_count),
        reply_count: parseInt(post.reply_count),
        is_liked_by_current_user: post.is_liked_by_current_user === 1,
        replies: replies
    };
}

// Create a new post
async function createPost(user_id, content) {
    const [result] = await pool.query(
        'INSERT INTO posts (user_id, content) VALUES (?, ?)',
        [user_id, content]
    );
    return result.insertId;
}

// Add a like to a post
async function addLike(postId, userId) {
    const [result] = await pool.query(`
        INSERT IGNORE INTO likes (post_id, user_id)
        VALUES (?, ?)
    `, [postId, userId]);

    return result.affectedRows > 0;
}

// Remove a like from a post (Unlike)
async function removeLike(postId, userId) {
    const [result] = await pool.query(
        'DELETE FROM likes WHERE post_id = ? AND user_id = ?',
        [postId, userId]
    );
    return result.affectedRows;
}

// Add a reply to a post
async function addReply(postId, user_id, content) {
    const [result] = await pool.query(
        'INSERT INTO replies (post_id, user_id, content) VALUES (?, ?, ?)',
        [postId, user_id, content]
    );
    return result.insertId;
}


// --- PRIVATE CHAT (DM) FUNCTIONS ---

// Fetch private chat history
async function getChatHistory(user1Id, user2Id) {
    const [rows] = await pool.query(
        `SELECT
            pm.sender_id,
            pm.recipient_id,
            pm.content,
            pm.sent_at,
            -- File metadata for preview/download
            uf.file_id,
            uf.storage_path,
            uf.original_filename,
            uf.mime_type
        FROM
            private_messages pm
        -- LEFT JOIN ensures text messages (where file_id is NULL) are still included
        LEFT JOIN uploaded_files uf ON pm.file_id = uf.file_id
        WHERE
            (pm.sender_id = ? AND pm.recipient_id = ?) OR (pm.sender_id = ? AND pm.recipient_id = ?)
        ORDER BY
            pm.sent_at ASC`,
        [user1Id, user2Id, user2Id, user1Id]
    );

    // 🟢 Add message_type for client-side rendering logic
    return rows.map(row => ({
        ...row,
        message_type: row.file_id ? 'file' : 'text'
    }));
}
// Save a private message
async function saveMessage(senderId, recipientId, content, fileId = null) {
    const [result] = await pool.query(
        'INSERT INTO private_messages (sender_id, recipient_id, content, file_id) VALUES (?, ?, ?, ?)',
        [senderId, recipientId, content, fileId]
    );
    return result.insertId;
}

async function markPrivateMessagesAsRead(senderId, recipientId) {
    // Note: Assumes senderId is the ID of the person who sent the unread messages,
    // and recipientId is the ID of the current user (the reader).
    const [result] = await pool.query(
        `UPDATE private_messages
         SET is_read = 1
         WHERE sender_id = ? AND recipient_id = ? AND is_read = 0`,
        [senderId, recipientId]
    );
    return result.affectedRows;
}
// --- PASSWORD RESET FUNCTIONS ---



// Update a user's password (OTP verification is assumed complete by caller)
async function resetPassword(userId, newHashedPassword) {
    const [result] = await pool.query(
        'UPDATE users SET password_hash = ? WHERE user_id = ?',
        [newHashedPassword, userId]
    );
    return result.affectedRows;
}


// --- GROUP CHAT FUNCTIONS ---

// Create a new group and return the group_id
async function createGroup(name, creatorId) {
    const [result] = await pool.query(
        'INSERT INTO `groups` (group_name, creator_id) VALUES (?, ?)',
        [name, creatorId]
    );
    return result.insertId;
}

// Add a user to a group
async function addGroupMember(groupId, userId) {
    const [result] = await pool.query(
        'INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)',
        [groupId, userId]
    );
    return result.affectedRows;
}

// Remove a user from a group
async function removeGroupMember(groupId, userId) {
    const [result] = await pool.query(
        'DELETE FROM group_members WHERE group_id = ? AND user_id = ?',
        [groupId, userId]
    );
    return result.affectedRows;
}

// Fetch basic details for a single group
async function getGroupDetails(groupId) {
    const [rows] = await pool.query(`
        SELECT
            g.group_id,
            g.group_name,
            g.creator_id,
            u.username AS creator_username
        FROM \`groups\` g
        JOIN users u ON g.creator_id = u.user_id
        WHERE g.group_id = ?
    `, [groupId]);
    return rows[0];
}

// Fetch all group IDs a user belongs to
async function getUserGroupIds(userId) {
    const [rows] = await pool.query(
        'SELECT group_id FROM group_members WHERE user_id = ?',
        [userId]
    );
    return rows.map(row => row.group_id);
}

// Fetch basic details for all groups a user belongs to
async function getUserGroups(userId) {
    const [rows] = await pool.query(`
        SELECT
            g.group_id,
            g.group_name,
            u.username AS creator_username,
            (SELECT COUNT(*) FROM group_members WHERE group_id = g.group_id) AS member_count,
            (SELECT MAX(sent_at) FROM group_messages WHERE group_id = g.group_id) AS last_activity
        FROM \`groups\` g -- **CORRECTION 1: Backticks added here**
        JOIN group_members gm ON g.group_id = gm.group_id
        JOIN users u ON g.creator_id = u.user_id
        WHERE gm.user_id = ?
        ORDER BY g.group_id DESC
    `, [userId]);
    // NOTE: The server-side error was caused by the SQL query.
    // The previous schema you showed had a typo (crCREATEeator_id), 
    // but the SQL query here uses g.creator_id, which assumes the typo 
    // has been corrected in the database schema.
    return rows;
}

// Save a group message
async function saveGroupMessage(groupId, senderId, content) {
    const [result] = await pool.query(
        'INSERT INTO group_messages (group_id, sender_id, content) VALUES (?, ?, ?)',
        [groupId, senderId, content]
    );
    return result.insertId;
}

// Fetch chat history for a group
async function getGroupChatHistory(groupId) {
    const [rows] = await pool.query(`
        SELECT
            m.message_id AS id,
            m.content,
            m.sent_at,
            u.username AS sender_username
        FROM group_messages m
        JOIN users u ON m.sender_id = u.user_id
        WHERE m.group_id = ?
        ORDER BY m.sent_at ASC
    `, [groupId]);

    return rows.map(row => ({
        id: row.id,
        content: row.content,
        sent_at: row.sent_at,
        sender_username: row.sender_username,
        groupId: parseInt(groupId)
    }));
}

// Check if a user is a member of a group
async function isGroupMember(groupId, userId) {
    const [rows] = await pool.query(
        'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
        [groupId, userId]
    );
    return rows.length > 0;
}

// Get all members of a specific group
async function getGroupMembers(groupId) {
    const [rows] = await pool.query(`
        SELECT
            u.user_id,
            u.username
        FROM users u
        JOIN group_members gm ON u.user_id = gm.user_id
        WHERE gm.group_id = ?
    `, [groupId]);
    return rows;
}


// ---------------------------------------------
// --- FILE UPLOAD FUNCTIONS ---
// ---------------------------------------------

// Save metadata for an uploaded file and return the new file_id
async function saveFileMetadata({ uploaderId, originalFilename, mimeType, storagePath, fileSizeBytes, groupId, recipientId }) {
    // This function inserts file metadata into the 'uploaded_files' table.
    const [result] = await pool.query(
        `INSERT INTO uploaded_files
         (uploader_id, original_filename, mime_type, storage_path, file_size_bytes, group_id, recipient_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        // Use 'null' for the group_id or recipient_id if they are not provided (e.g., if it's a private chat, groupId is null)
        [uploaderId, originalFilename, mimeType, storagePath, fileSizeBytes, groupId || null, recipientId || null]
    );
    return result.insertId;
}


// --- AI CHAT FUNCTIONS (NEW) ---

/**
 * Saves a single message (user or model) to the AI chat history.
 * @param {number} userId - The user's database ID.
 * @param {string} role - 'user' or 'model'.
 * @param {string} content - The message content.
 */
async function saveAIChatMessage(userId, role, content) {
    const [result] = await pool.query(
        `INSERT INTO ai_chat_messages (user_id, role, content)
         VALUES (?, ?, ?)`,
        [userId, role, content]
    );
    return result.insertId;
}

/**
 * Retrieves the full AI chat history for a user, formatted for the Gemini API.
 * @param {number} userId - The user's database ID.
 * @returns {Array<{role: string, parts: Array<{text: string}>}>}
 */
async function getAIChatHistory(userId) {
    const [rows] = await pool.query(
        `SELECT role, content
         FROM ai_chat_messages
         WHERE user_id = ?
         ORDER BY created_at ASC`,
        [userId]
    );
    // Transform the result to the format: [{role: 'user/model', parts: [{text: '...'}]}]
    return rows.map(row => ({
        role: row.role,
        parts: [{ text: row.content }]
    }));
}

 // Function to save a user support concern to the database
async function saveSupportTicket(userId, username, email, concern) {
    // **CORRECTION 2: Replaced incorrect sqlite/db.run with pool.query for mysql2**
    try {
        const sql = `INSERT INTO support_tickets (user_id, username, email, concern) VALUES (?, ?, ?, ?)`;
        const [result] = await pool.query(sql, [userId, username, email, concern]);
        return result.insertId; // Return the new ticket ID
    } catch (err) {
        console.error("Database error saving support ticket:", err);
        throw err; // Re-throw the error for the caller to handle
    }
}
// --- MODULE EXPORTS ---

module.exports = {
    // Basic helpers
    pool,
    findUserByUsername,
    findUserIdByUsername,
    findUserByEmail,
    createUser,
    getAllUsers,

    // Social Feed
    getPublicPosts,
    getPostById,
    createPost,
    addLike,
    removeLike,
    addReply,

    // Private Chat
    getChatHistory,
    saveMessage,
    markPrivateMessagesAsRead,

    // Password Reset
   
    resetPassword,

    // Group Chat
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

    // File Upload (NEW)
    saveFileMetadata,

    // AI Chat (NEW)
    saveAIChatMessage,
 getAIChatHistory,
// virtual assistant
saveSupportTicket,

};
