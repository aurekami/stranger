const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const CryptoJS = require('crypto-js'); // Add CryptoJS library

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Encryption function
function encryptMessage(message, key) {
  return CryptoJS.AES.encrypt(message, key).toString();
}

// Decryption function
function decryptMessage(encryptedMessage, key) {
  return CryptoJS.AES.decrypt(encryptedMessage, key).toString(CryptoJS.enc.Utf8);
}

// Routes
app.get('/', (req, res) => {
  res.send('Welcome to Signal Messaging App');
});

// MongoDB connection
mongoose.connect('mongodb://127.0.0.1:27017/signal-messaging-app')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Failed to connect to MongoDB', err));

// User model
const User = mongoose.model('User', new mongoose.Schema({
  username: String,
  password: String
}));

// User signup
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword });
  await user.save();
  res.status(201).send('User created successfully');
});

// User login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).send('Invalid username or password');
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).send('Invalid username or password');
  const token = jwt.sign({ userId: user._id }, secretKey);
  res.send(token);
});

// Route for sending messages
app.post('/send-message', (req, res) => {
  const { message, recipientPublicKey } = req.body;
  // Encrypt the message using recipient's public key
  const encryptedMessage = encryptMessage(message, recipientPublicKey);
  // Send the encrypted message to the recipient
  // (Implementation of sending message to recipient is not included in this example)
  res.send('Message sent successfully');
});

// Route for receiving messages
app.post('/receive-message', (req, res) => {
  const { encryptedMessage, senderPublicKey } = req.body;
  // Decrypt the message using sender's public key
  const decryptedMessage = decryptMessage(encryptedMessage, senderPublicKey);
  // Display the decrypted message to the recipient
  res.send(decryptedMessage);
});

// Middleware for user authentication
function authenticateUser(req, res, next) {
  // Check if username and password are provided in the request body
  const { username, password } = req.body;
  if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
  }
  // Check if the username and password are valid (e.g., compare with database)
  // If valid, generate a token and attach it to the request object
  const token = generateToken(username); // Example function to generate token
  req.token = token;
  next();
}

// Example function to generate token (using JSON Web Tokens)
function generateToken(username) {
  // Generate a JWT token with username as payload
  return jwt.sign({ username }, secretKey, { expiresIn: '1h' });
}

// User login route
app.post('/login', authenticateUser, (req, res) => {
  // Return the generated token
  res.json({ token: req.token });
});

// Example secure route that requires authentication
app.post('/send-message', authenticateUser, (req, res) => {
  // Only authenticated users can access this route
  // Send message functionality
  res.send('Message sent successfully');
});

// Middleware for authorization
function authorizeAdmin(req, res, next) {
  // Decode token and check user's role
  const token = req.headers.authorization.split(' ')[1];
  const decodedToken = jwt.verify(token, secretKey);
  if (decodedToken.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
  }
  next();
}

// Example secure route that requires admin authorization
app.post('/admin-route', authorizeAdmin, (req, res) => {
  // Only admins can access this route
  // Admin functionality
  res.send('Admin functionality');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});


const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
exports.userSchema = userSchema;





