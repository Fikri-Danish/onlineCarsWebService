// include the required packages
const express = require('express');
const mysql = require('mysql2/promise');
require('dotenv').config();
const port = 3000;

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 100,
    queueLimit: 0,
};

// intialize Express app
const app = express();

const cors = require("cors");

const allowedOrigins = [
    "http://localhost:3000",
    "https://onlinecarswebservice.onrender.com/allcars",
];

app.use(
    cors({
        origin: function (origin, callback) {
            // allow requests with no origin (Postman/server-to-server)
            if (!origin) return callback(null, true);

            if (allowedOrigins.includes(origin)) {
                return callback(null, true);
            }
            return callback(new Error("Not allowed by CORS"));
        },
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
        credentials: false,
    })
);

// helps app to read JSON
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

const jwt = require("jsonwebtoken");

app.listen(port, () => {
    console.log('Server running on port', port);
});

// Get all study spaces
app.get('/allspaces', async (req, res) => {
    try {
        let connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT * FROM defaultdb.study_spaces');
        await connection.end();
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error for allspaces' });
    }
});

// Create a new study space - ADMIN ONLY
app.post('/addspace', requireAuth, requireAdmin, async (req, res) => {
    const { space_name, location, capacity, zone_type, is_available, booked_by, booking_time, space_image } = req.body;
    try {
        let connection = await mysql.createConnection(dbConfig);
        await connection.execute(
            'INSERT INTO study_spaces (space_name, location, capacity, zone_type, is_available, booked_by, booking_time, space_image) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
            [space_name, location, capacity, zone_type, is_available ?? true, booked_by ?? null, booking_time ?? null, space_image ?? null]
        );
        await connection.end();
        res.status(201).json({ message: 'Study space ' + space_name + ' added successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error - could not add study space ' + space_name });
    }
});

// Edit (update) a study space - ADMIN ONLY
app.put('/editspace/:id', requireAuth, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { space_name, location, capacity, zone_type, is_available, booked_by, booking_time, space_image } = req.body;

    if (space_name === undefined && location === undefined && capacity === undefined && zone_type === undefined && is_available === undefined && booked_by === undefined && booking_time === undefined && space_image === undefined) {
        return res.status(400).json({ message: 'Nothing to update' });
    }

    try {
        let connection = await mysql.createConnection(dbConfig);
        const [result] = await connection.execute(
            `UPDATE defaultdb.study_spaces 
             SET space_name = COALESCE(?, space_name),
                 location = COALESCE(?, location),
                 capacity = COALESCE(?, capacity),
                 zone_type = COALESCE(?, zone_type),
                 is_available = COALESCE(?, is_available),
                 booked_by = COALESCE(?, booked_by),
                 booking_time = COALESCE(?, booking_time),
                 space_image = COALESCE(?, space_image)
             WHERE id = ?`,
            [space_name ?? null, location ?? null, capacity ?? null, zone_type ?? null, is_available ?? null, booked_by ?? null, booking_time ?? null, space_image ?? null, id]
        );
        await connection.end();

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Study space not found' });
        }

        res.json({ message: 'Study space id ' + id + ' updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error - could not update study space id ' + id });
    }
});

// Delete a study space - ADMIN ONLY
app.delete('/deletespace/:id', requireAuth, requireAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        let connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('DELETE FROM defaultdb.study_spaces WHERE id = ?', [id]);
        await connection.end();
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error for deletespace' });
    }
});

// Login endpoint - uses users table
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and password required" });
    }

    try {
        let connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute(
            'SELECT userId, username, password, email, role FROM defaultdb.users WHERE username = ?',
            [username]
        );
        await connection.end();

        if (rows.length === 0) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const user = rows[0];

        // Plain text password comparison
        if (password !== user.password) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { 
                userId: user.userId, 
                username: user.username,
                role: user.role 
            },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({ 
            token,
            user: {
                userId: user.userId,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error during login" });
    }
});

function requireAuth(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: "Missing Authorization header" });

    const [type, token] = header.split(" ");
    if (type !== "Bearer" || !token) {
        return res.status(401).json({ error: "Invalid Authorization format" });
    }

    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;
        next();
    } catch {
        return res.status(401).json({ error: "Invalid/Expired token" });
    }
}

// Middleware to require admin role
function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: "Access denied. Admin role required." });
    }
    next();
}

// Middleware to require student or admin role
function requireStudentOrAdmin(req, res, next) {
    if (req.user.role !== 'student' && req.user.role !== 'admin') {
        return res.status(403).json({ error: "Access denied. Student or Admin role required." });
    }
    next();
}