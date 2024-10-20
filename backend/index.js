const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const userRoutes = require('./routes/userRoutes');
const clubRoutes = require('./routes/clubRoutes');

const app = express();

app.use(express.json({ limit: '100mb' }));
app.use(cors({
    origin: '*',
    methods: ["POST", "GET", "DELETE"],
    credentials: true
}));
app.use(cookieParser());

app.use('/', (req, res) => {
    res.json({ message: "Hello welcome to khelkhoj" });
});

app.use('/user', userRoutes);
app.use('/club', clubRoutes);

module.exports = app; // Export the app
