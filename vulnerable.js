const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const fs = require('fs');
const xml2js = require('xml2js');
const serialize = require('node-serialize');
const crypto = require('crypto');
const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

app.use(session({
    secret: 'secretkey123',
    resave: true,
    saveUninitialized: true,
    cookie: {}
}));

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'vulnerable_app'
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to database');
});

app.get('/users', (req, res) => {
    const id = req.query.id;
    const query = `SELECT * FROM users WHERE id = ${id}`;

    db.query(query, (err, result) => {
        if (err) throw err;
        res.json(result);
    });
});

app.get('/profile', (req, res) => {
    const username = req.query.username;
    res.send(`
    <html>
      <body>
        <h1>Welcome, ${username}!</h1>
      </body>
    </html>
  `);
});

app.get('/admin/dashboard', (req, res) => {
    res.send('Admin Dashboard - All user data here');
});

app.post('/process-xml', (req, res) => {
    const xmlData = req.body.xml;

    const parser = new xml2js.Parser({
        explicitArray: false,
        xmlns: true
    });

    parser.parseString(xmlData, (err, result) => {
        if (err) {
            res.status(500).send('Error parsing XML');
        } else {
            res.json(result);
        }
    });
});

app.get('/deserialize', (req, res) => {
    const userDataEncoded = req.cookies.userData;

    if (userDataEncoded) {
        const userData = serialize.unserialize(Buffer.from(userDataEncoded, 'base64').toString());
        res.json(userData);
    } else {
        res.send('No user data found');
    }
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    db.query(query, (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            console.log(`User logged in: ${username}, ${password}, ${results[0].email}`);

            res.cookie('credentials', JSON.stringify({
                username: username,
                password: password
            }));

            res.send('Login successful');
        } else {
            res.status(401).send('Invalid credentials');
        }
    });
});

app.get('/debug', (req, res) => {
    res.json({
        environment: 'production',
        database: {
            host: db.config.host,
            user: db.config.user,
            password: db.config.password,
            database: db.config.database
        },
        serverInfo: process.env
    });
});

let loginAttempts = {};

app.post('/login-no-rate-limit', (req, res) => {
    const { username, password } = req.body;

    if (username === 'admin' && password === 'secretpassword123') {
        res.send('Login successful');
    } else {
        res.status(401).send('Invalid credentials');
    }
});

app.get('/download', (req, res) => {
    const filename = req.query.file;

    const filePath = `./public/files/${filename}`;

    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.status(404).send('File not found');
        } else {
            res.send(data);
        }
    });
});

const http = require('http');

app.get('/fetch-resource', (req, res) => {
    const url = req.query.url;

    http.get(url, (response) => {
        let data = '';

        response.on('data', (chunk) => {
            data += chunk;
        });

        response.on('end', () => {
            res.send(data);
        });
    }).on('error', (err) => {
        res.status(500).send('Error fetching resource');
    });
});

app.post('/transfer', (req, res) => {
    const { to, amount } = req.body;

    if (req.session.loggedIn) {
        res.send(`Transferred $${amount} to ${to}`);
    } else {
        res.status(401).send('Not logged in');
    }
});

app.listen(port, () => {
    console.log(`Vulnerable app listening at http://localhost:${port}`);
});

app.use((err, req, res, next) => {
    console.error('Something broke!');
    res.status(500).send('Server error');
});

module.exports = app;