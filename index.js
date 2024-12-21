// Importing required modules
const express = require('express');
const session = require('express-session');
const flash = require('express-flash');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const app = express();
require("dotenv").config() ;

app.use(session({
    secret: 'your-secret-key', // Change this to a real secret
    resave: false,
    saveUninitialized: true
}));
app.use(flash());
// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// Environment variables
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI
const JWT_SECRET = process.env.JWT_SECRET;

// MongoDB connection
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.log(err));

// User schema and model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});
const User = mongoose.model('User', userSchema);

// Task schema and model
const taskSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    description: { type: String },
    completed: { type: Boolean, default: false },
});
const Task = mongoose.model('Task', taskSchema);

// Helper function to verify token
const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.redirect('/login');
        req.userId = decoded.id;
        next();
    });
};

app.use((req, res, next) => {
    res.locals.successMessage = req.cookies.successMessage || '';
    res.clearCookie('successMessage');
    next();
});
// Routes
app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login', { successMessage: res.locals.successMessage });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.render('login', { error: 'Invalid credentials', successMessage: '' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.render('login', { error: 'Invalid credentials', successMessage: '' });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    res.cookie('successMessage', 'Login successful!');
    res.redirect('/tasks');
});

app.get('/signup', (req, res) => {
    const errors = [];
    res.render('signup',{ errors: errors });
});

app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Check if email or username already exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.render('signup', { error: 'Email or username already in use' });
        }

        // Hash the password and create the user
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ username, email, password: hashedPassword });
        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.render('signup', { error: 'An error occurred while creating the account' });
    }
});

app.get('/tasks', verifyToken, async (req, res) => {
    const tasks = await Task.find({ userId: req.userId });
    res.render('tasks', { tasks });
});

app.post('/tasks', verifyToken, async (req, res) => {
    const { title, description } = req.body;
    await Task.create({ userId: req.userId, title, description });
    res.redirect('/tasks');
});

app.post('/tasks/:id/delete', verifyToken, async (req, res) => {
    await Task.findByIdAndDelete(req.params.id);
    res.redirect('/tasks');
});

app.get('/tasks/:id/edit', async (req, res) => {
    const taskId = req.params.id;
    try {
        const task = await Task.findById(taskId);
        if (!task) {
            return res.status(404).send('Task not found');
        }
        res.render('editTask', { task });
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

app.post('/tasks/:id/edit', async (req, res) => {
    const taskId = req.params.id;
    const { title, description } = req.body;
    try {
        await Task.findByIdAndUpdate(taskId, { title, description });
        res.redirect('/tasks');
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});