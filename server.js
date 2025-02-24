const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const socketIo = require('socket.io');

dotenv.config();
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());  // Enable Cross-Origin Resource Sharing

// Rate limiting for login and send-message
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: "Too many login attempts, please try again later."
});

const messageLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // Limit each IP to 10 messages per windowMs
  message: "Too many messages, please try again later."
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.log("Error connecting to MongoDB Atlas", err));

// User model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profilePic: String,
  bio: String,
  isOnline: { type: Boolean, default: false }
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const User = mongoose.model('User', userSchema);

// Message model
const messageSchema = new mongoose.Schema({
  sender: String,
  receiver: String,
  message: String,
  timestamp: { type: Date, default: Date.now },
  deleted: { type: Boolean, default: false },
  read: { type: Boolean, default: false }
});

const Message = mongoose.model('Message', messageSchema);

// Middleware to protect routes
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ message: 'Authorization required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Socket.io setup
let users = {};  // Store online users by socket ID
const server = app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

const io = socketIo(server);

// Socket.io events
io.on('connection', (socket) => {
  console.log('New client connected');
  
  // Mark user as online
  socket.on('user-online', (userId) => {
    users[socket.id] = userId;
    User.findByIdAndUpdate(userId, { isOnline: true }, { new: true });
    io.emit('user-status-change', { userId, isOnline: true });
  });

  // Typing indicator
  socket.on('typing', (data) => {
    socket.broadcast.emit('typing', data);  // Broadcast typing status to the other users
  });

  // Send message
  socket.on('send-message', (data) => {
    io.emit('new-message', data);  // Broadcast message to all connected clients
  });

  // User disconnect
  socket.on('disconnect', () => {
    const userId = users[socket.id];
    if (userId) {
      User.findByIdAndUpdate(userId, { isOnline: false }, { new: true });
      io.emit('user-status-change', { userId, isOnline: false });
      delete users[socket.id];
    }
  });
});

// Routes

// Register route
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const newUser = new User({ username, email, password });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error registering user', error: error.message });
  }
});

// Login route
app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(200).json({ message: 'Login successful', token, refreshToken });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
});

// Send message route (no file support)
app.post('/send-message', authenticate, messageLimiter, async (req, res) => {
  const { sender, receiver, message } = req.body;

  try {
    const newMessage = new Message({ sender, receiver, message });
    await newMessage.save();
    res.status(201).json({ message: "Message sent successfully", data: newMessage });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ message: "Error sending message", error: error.message });
  }
});

// Get messages route
app.get('/messages/:sender/:receiver', authenticate, async (req, res) => {
  const { sender, receiver } = req.params;

  try {
    const messages = await Message.find({ $or: [{ sender, receiver }, { sender: receiver, receiver: sender }] })
      .sort({ timestamp: 1 });

    res.status(200).json({ messages });
  } catch (error) {
    console.error("Error retrieving messages:", error);
    res.status(500).json({ message: "Error retrieving messages", error: error.message });
  }
});

// Mark message as read route (Fixed the error)
app.put('/mark-read/:id', authenticate, async (req, res) => {
  const { id } = req.params; // Extract message ID from URL

  try {
    const message = await Message.findById(id); // Find the message by ID
    if (!message) {
      return res.status(404).json({ message: 'Message not found' });
    }

    // Check if the message receiver is the logged-in user
    if (message.receiver !== req.userId) {
      return res.status(403).json({ message: 'Not authorized to mark this message as read' });
    }

    message.read = true; // Mark the message as read
    await message.save(); // Save the updated message

    res.status(200).json({ message: 'Message marked as read' });
  } catch (error) {
    console.error("Error marking message as read:", error);
    res.status(500).json({ message: 'Error marking message as read', error: error.message });
  }
});

// User Profile route
app.get('/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    res.status(200).json({ username: user.username, email: user.email, profilePic: user.profilePic, bio: user.bio });
  } catch (error) {
    console.error("Error fetching profile:", error);
    res.status(500).json({ message: "Error fetching profile", error: error.message });
  }
});

// Update Profile route
app.put('/profile', authenticate, async (req, res) => {
  const { profilePic, bio } = req.body;

  try {
    const user = await User.findByIdAndUpdate(req.userId, { profilePic, bio }, { new: true });
    res.status(200).json({ message: "Profile updated successfully", user });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ message: "Error updating profile", error: error.message });
  }
});
