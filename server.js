// include the required packages
const express = require('express');
const mysql = require('mysql2/promise');
require('dotenv').config();
const jwt = require('jsonwebtoken');
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

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

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

app.listen(port, () => {
    console.log('Server running on port', port);
});

// Login endpoint
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

// Middleware to require authentication
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

// Middleware to require customer or admin role
function requireCustomerOrAdmin(req, res, next) {
    if (req.user.role !== 'customer' && req.user.role !== 'admin') {
        return res.status(403).json({ error: "Access denied. Customer or Admin role required." });
    }
    next();
}

// Example Route: Get all cars (public or require auth based on your needs)
app.get('/allcars', async (req, res) => {
    try {
        let connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT * FROM defaultdb.cars');
        await connection.end();
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error for allcars' });
    }
});

// Create a new car - Admin only
app.post('/addcar', requireAuth, requireAdmin, async (req, res) => {
    const { car_name, car_description, brand, price, year, stocks, car_image } = req.body;
    try {
        let connection = await mysql.createConnection(dbConfig);
        await connection.execute(
            'INSERT INTO cars (car_name, car_description, brand, price, year, stocks, car_image) VALUES (?, ?, ?, ?, ?, ?, ?)', 
            [car_name, car_description, brand, price, year, stocks, car_image]
        );
        await connection.end();
        res.status(201).json({ message: 'Car '+car_name+' added successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error - could not add car '+car_name});
    }
});

// Edit (update) a car - Admin only
app.put('/editcar/:id', requireAuth, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { car_name, car_description, brand, price, year, stocks, car_image } = req.body;

    if (car_name === undefined && car_description === undefined && brand === undefined && price === undefined && year === undefined && stocks === undefined && car_image === undefined) {
        return res.status(400).json({ message: 'Nothing to update' });
    }

    try {
        let connection = await mysql.createConnection(dbConfig);
        const [result] = await connection.execute(
            `UPDATE defaultdb.cars 
             SET car_name = COALESCE(?, car_name),
                 car_description = COALESCE(?, car_description),
                 brand = COALESCE(?, brand),
                 price = COALESCE(?, price),
                 year = COALESCE(?, year),
                 stocks = COALESCE(?, stocks),
                 car_image = COALESCE(?, car_image)
             WHERE id = ?`,
            [car_name ?? null, car_description ?? null, brand ?? null, price ?? null, year ?? null, stocks ?? null, car_image ?? null, id]
        );
        await connection.end();

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Car not found' });
        }

        res.json({ message: 'Car id ' + id + ' updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error - could not update car id ' + id });
    }
});

// Delete a car - Admin only
app.delete('/deletecar/:id', requireAuth, requireAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        let connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('DELETE FROM defaultdb.cars WHERE id = ?', [id]);
        await connection.end();
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error for deletecar' });
    }
});