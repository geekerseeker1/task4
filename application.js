const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = 3000;

const connection = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE_NAME,
});

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: true }));


app.use(express.static('public'));


app.get('/register', (req, res) => {
  res.render('registration');
});


app.post('/register', async (req, res) => {
  const { firstname, lastname, username, password } = req.body;

  try {
    
    const hashedPassword = await bcrypt.hash(password, 10);

   
    const sql = 'INSERT INTO users (firstname, lastname, username, password) VALUES (?, ?, ?, ?)';
    connection.query(sql, [firstname, lastname, username, hashedPassword], (err, result) => {
      if (err) throw err;
      res.redirect('/details/' + result.insertId);
    });
  } catch (error) {
    res.status(500).send('An error occurred during registration.');
  }
});


app.get('/details/:id', authenticateToken, (req, res) => {
  const userId = req.params.id;

  
  const sql = 'SELECT * FROM users WHERE id = ?';
  connection.query(sql, [userId], (err, result) => {
    if (err) throw err;
    const user = result[0];
    res.render('userdetails', { user });
  });
});


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
   

