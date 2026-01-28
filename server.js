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


app.listen(port, () => {
    console.log('Server running on port', port);
});



// Example Route: Get all cars
app.get('/allcars', async (req, res) => {
    try {
        let connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT * FROM defaultdb.cars');
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error for allcars' });
    }
});

// Example Route: Create a new car
app.post('/addcar', async (req, res) => {
    const { car_name, car_description, brand, price, year, colour, car_image } = req.body;
    try {
        let connection = await mysql.createConnection(dbConfig);
        await connection.execute('INSERT INTO cars (car_name, car_description, brand, price, year, colour, car_image) VALUES (?, ?, ?, ?, ?, ?, ?)', [car_name, car_description, brand, price, year, colour, car_image]);
        res.status(201).json({ message: 'Car '+car_name+' added successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error - could not add car '+car_name});
    }
});

// Edit (update) a car
app.put('/editcar/:id', async (req, res) => {
    const { id } = req.params;
    const { car_name, car_description, brand, price, year, colour, car_image } = req.body;

    if (car_name === undefined && car_description === undefined, brand === undefined && price === undefined && year === undefined && colour === undefined && car_image) {
        return res.status(400).json({ message: 'Nothing to update' });
    }

    try {
        let connection = await mysql.createConnection(dbConfig);
        const [result] = await connection.execute(
            `UPDATE defaultdb.cars 
             SET car_name = COALESCE(?, car_name),
                 car_description = COALESCE(?, car_description)
                 brand = COALESCE(?, brand),
                 price = COALESCE(?, price),
                 year = COALESCE(?, year),
                 colour = COALESCE(?, colour),
                 car_image = COALESCE(?, car_image)
             WHERE id = ?`,
            [car_name ?? null, car_description ?? null, brand ?? null, price ?? null, year ?? null, colour ?? null, car_image ?? null, id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Car not found' });
        }

        res.json({ message: 'Car id ' + id + ' updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error - could not update car id ' + id });
    }
});

app.delete('/deletecar/:id', async (req, res) => {
    const { id } = req.params;
    try {
        let connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('DELETE FROM defaultdb.cars WHERE id = ?', [id]);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error for deletecar' });
    }
});