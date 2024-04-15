const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const multer = require('multer');
const flash = require('connect-flash');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Session configuration
app.use(session({
    store: new SQLiteStore({ db: 'sessionsDB.sqlite', dir: './' }),
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Flash messages
app.use(flash());

// Logging middleware
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url} - Body:`, req.body);
    next();
});

// Set views and static directory
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Multer configuration
const storage = multer.diskStorage({
    destination: './public/uploads/',
    filename: function(req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }
});

// Initialize body parser for JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// SQLite database
const db = new sqlite3.Database('./users.db');

// Create users table
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)`);

// Middleware to pass flash messages to views
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.username = req.session.username;
    next();
});

// GET route for register
app.get('/register', (req, res) => {
    res.render('register');
});

// GET route for login
app.get('/login', (req, res) => {
    res.render('login');
});

// GET route for login
app.get('/logout', (req, res) => {
    res.render('login');
});


// Middleware to check if user is logged in
function isLoggedIn(req, res, next) {
    if (req.session.username) {
        next();
    } else {
        req.flash('error_msg', 'Please log in to upload files.');
        res.redirect('/login');
    }
}

// Routes
app.get('/', isLoggedIn, (req, res) => {
    const dir = './public/uploads';
    
    fs.readdir(dir, (err, files) => {
        if (err) {
            console.error(err);
            res.status(500).send('Internal Server Error');
            return;
        }
        
        res.render('index', { files });
    });
});

// User registration
app.post('/register', async (req, res) => {
    console.log('Register request body:', req.body);

    if (!req.body || !req.body.username || !req.body.password) {
        return res.status(400).send('Invalid request');
    }

    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
        if (err) {
            return res.status(500).send(err.message);
        }
        req.session.username = username;
        res.redirect('/login');
    });
});

// User login
app.post('/login', async (req, res) => {
    console.log('Login request body:', req.body);

    if (!req.body || !req.body.username || !req.body.password) {
        return res.status(400).send('Invalid request');
    }

    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) {
            return res.status(500).send(err.message);
        }

        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(400).send("Invalid username or password!");
        }

        req.session.username = username;
        res.redirect('/');
    });
});

// Upload route
app.post('/upload', upload.single('file'), (req, res) => {
    const file = req.file;
    if (!file) {
        req.flash('error_msg', 'No file uploaded.');
        return res.redirect('/');
    }
    const filePath = `/uploads/${file.filename}`;
    const fileUrl = `cdn.sastaflash.fun${filePath}`;
    req.flash('success_msg', `File uploaded successfully: <a href="${fileUrl}" target="_blank">${fileUrl}</a>`);
    res.redirect('/');
});

// Delete route
app.delete('/delete/:filename', (req, res) => {
    const filePath = path.join(__dirname, 'public/uploads', req.params.filename);
    
    fs.unlink(filePath, (err) => {
        if (err) {
            console.error(err);
            return res.json({ success: false });
        }
        res.json({ success: true });
    });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
