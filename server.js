const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const dotenv = require("dotenv").config();
const ejs = require('ejs');
const path = require("path");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");

const app = express();
const port = process.env.PORT || 8080;

app.use(session({
    secret: process.env.SECRET,
    resave:false,
    saveUninitialized: false
    //cookie: { secure: true }
 }));

//serving JS and HTML using EJS
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

//serving our static files then Middleware
app.use(express.static(path.join(__dirname, 'static')));

app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true }));

// MYSQL connection
const dbconnection = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
});

module.exports = dbconnection;

// Connecting to MySQL DB
dbconnection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL: ' + err);
        return;
    }
    console.log('Connected to MySQL as id ' + dbconnection.threadId);
});

const security = (req,res,next) => {
    if (req.session.user) {
        next(); // User is authenticated, continue to next middleware
    } else {
        res.redirect('/signin'); // User is not authenticated, redirect to login page
    } }

function clearInput(){
    document.querySelector('.email').value = "";
    document.querySelector('.name').value = "";
    document.querySelector('.texts').value = "";
}   

//Routes
app.get('/', (req, res) => { 
    res.sendFile(__dirname + '/index.html');
});
app.get('/signin', (req, res) => { 
    res.sendFile(__dirname + '/SignIN.html');
});
app.get('/home',security, (req, res) => { 
    res.render('home.ejs');
});
app.get('/logout',security, (req, res) =>{
     res.sendFile(__dirname + '/logout.html')
})
app.get('/logoutyes',security, (req, res) =>{
      req.session.destroy(err => {
        if (err) {
          res.status(400).send('Unable to log out')
        } else {
          res.send('Logout successful')
        }
      });
     // res.redirect('/signin');  
})



// Insert user into MySQL
app.post('/', async (req, res) => {
    const Name = req.body.name;
    const Contact = req.body.contact;
    const Email = req.body.email;
    const password = req.body.password;
       //Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    dbconnection.query("INSERT INTO users (Name, Contact, Email, Password) VALUES (?,?,?,?)",[Name,Contact,Email,hashedPassword], (err, results) => {
        if(err){
          console.log(err)
          res.send('THERE WAS AN ERROR, PLEASE TRY AGAIN!')
        }else {
          req.session.user = results; 
          console.log('Inserted a new user with id ' + results.insertId);
          res.redirect('/home')
        }
    })
});
// Signing a user in
app.post('/signin', async (req, res) => {
    const Email = req.body.email;
    const password = req.body.password;   

    dbconnection.query("SELECT * FROM users WHERE Email = ?", [Email], (err, results) => {
        if(err){
          console.log(err)
        }else if (results.length < 1) {
            res.send("No such EMAIL found!!");
        }else {
            bcrypt.compare(password, results[0].Password, (err, match) => {
            req.session.user = results;
                if(match) {
                    res.redirect('/home');
                }else if (!match) {
                    res.status(418).send('WRONG PASSWORD!')
                }
            })
        }
    })
});
//Insert users message into MYSQL
 app.post('/home', async (req,res) => {
    const Name = req.body.name;
    const Email = req.body.email;
    const Message = req.body.message;
    dbconnection.query("INSERT INTO messages (Name, Email, Message) VALUES (?,?,?)",[Name,Email,Message], (err, results) => {
        if(err){
          console.log(err)
          res.send('THERE WAS AN ERROR, PLEASE TRY AGAIN!')
        }else {
            console.log('Message Sent');
            res.status(200).end();
        }
    })

 });


app.listen(port, ()=> {
    console.log(`listesning on port: ${port}`);
});