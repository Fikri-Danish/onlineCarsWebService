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
  "https://onlinestudyspaceswebservice.onrender.com/allspaces",
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



// Example Route: Get all study spaces
app.get('/allspaces', async (req, res) => {
    try {
        let connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT * FROM defaultdb.study_spaces');
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error for allspaces' });
    }
});

// Example Route: Create a new study space
app.post('/addspace', async (req, res) => {
    const { space_name, location, capacity, zone_type, is_available, booked_by, booking_time, space_image } = req.body;
    try {
        let connection = await mysql.createConnection(dbConfig);
        await connection.execute('INSERT INTO study_spaces (space_name, location, capacity, zone_type, is_available, booked_by, booking_time, space_image) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [space_name, location, capacity, zone_type, is_available, booked_by, booking_time, space_image]);
        res.status(201).json({ message: 'Study space '+space_name+' added successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error - could not add study space '+space_name});
    }
});

// Edit (update) a study space
app.put('/editspace/:id', async (req, res) => {
    const { id } = req.params;
    const { space_name, location, capacity, zone_type, is_available, booked_by, booking_time } = req.body;

    if (space_name === undefined && location === undefined, capacity === undefined && zone_type === undefined && is_available === undefined && booked_by === undefined && booking_time) {
        return res.status(400).json({ message: 'Nothing to update' });
    }

    try {
        let connection = await mysql.createConnection(dbConfig);
        const [result] = await connection.execute(
            `UPDATE defaultdb.study_spaces 
             SET space_name = COALESCE(?, space_name),
                 location = COALESCE(?, location)
                 capacity = COALESCE(?, capacity),
                 zone_type = COALESCE(?, zone_type),
                 is_available = COALESCE(?, is_available),
                 booked_by = COALESCE(?, booked_by),
                 booking_time = COALESCE(?, booking_time)
                 space_image = COALESCE(?, space_image)
             WHERE space_id = ?`,
            [space_name ?? null, location ?? null, capacity ?? null, zone_type ?? null, is_available ?? null, booked_by ?? null, booking_time ?? null, space_image ?? null, id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Study space not found' });
        }

        res.json({ message: 'Study space id ' + id + ' updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error - could not update study space id ' + id });
    }
});

app.delete('/deletespace/:id', async (req, res) => {
    const { id } = req.params;
    try {
        let connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('DELETE FROM defaultdb.study_spaces WHERE space_id = ?', [id]);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error for deletespace' });
    }
});
