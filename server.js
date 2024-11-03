require('dotenv').config(); 
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 5000;

// mongodbbbb connection
mongoose.connect('mongodb://localhost:27017/google-auth', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const UserSchema = new mongoose.Schema({
    googleId: String,
    displayName: String,
    email: String,
    password: String, // For email/password authentication
    phone: String,
});



const User = mongoose.model('User', UserSchema);

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
    const existingUser = await User.findOne({ googleId: profile.id });
    if (existingUser) {
        done(null, existingUser);
    } else {
        const newUser = await new User({
            googleId: profile.id,
            displayName: profile.displayName,
            email: profile.emails[0].value,
        }).save();
        done(null, newUser);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id).then((user) => {
        done(null, user);
    });
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret_key',
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
    // Successful authentication, redirect home
    res.send('You are logged in');
});


app.post('/signup', async (req, res) => {
    console.log(req.body); 
    const { name, email, phone, password } = req.body;

    if (!password) {
        return res.status(400).send('Password is required');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const user = new User({ 
            displayName: name, 
            email, 
            phone, 
            password: hashedPassword 
        });
        await user.save();

        console.log('User created:', user);
        res.send('User registered successfully!');
    } catch (error) {
        console.error('Error saving user:', error);
        res.status(500).send('Internal server error');
    }
});




app.post('/login', async (req, res) => {
    console.log(req.body); 
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email and password are required');
    }

    try {
        const user = await User.findOne({ email });
        
        console.log('Retrieved user:', user);

        if (!user) {
            return res.status(400).send('User not found');
        }

        if (!user.password) {
            return res.status(500).send('Password not found for this user');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        
        if (isMatch) {
            req.login(user, (err) => {
                if (err) return res.status(500).send('Login failed');
                return res.send('You are logged in');
            });
        } else {
            res.status(400).send('Invalid credentials');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal server error');
    }
});



// Start server so we can start
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}${PORT}`);
});



