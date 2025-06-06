// server.js
const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const cors = require('cors')
const authRoutes = require('./routes/authRoutes');

// Load environment variables
dotenv.config();

// Initialize express app
const app = express();
app.use(cors())
// Connect to MongoDB
connectDB();

// Middleware
app.use(express.json()); // for parsing JSON bodies

// Routes
app.use('/api/auth', authRoutes);

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
