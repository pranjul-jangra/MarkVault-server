const express = require("express");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// **User Schema**
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  refreshTokens: { type: [String], default: [] },
});
const User = mongoose.model("User", UserSchema);

// **Bookmark Schema**
const BookmarkSchema = new mongoose.Schema({
  title: String,
  url: String,
  category: String,
  tags: { type: [String], default: [] },
  notes: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
});
const Bookmark = mongoose.model("Bookmark", BookmarkSchema);

// **Generate Tokens**
const generateAccessToken = (user) => {
  if (!process.env.JWT_SECRET) {
    throw new Error("Missing JWT_SECRET in .env file");
  }
  return jwt.sign(
    { userId: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "15m" }
  );
};

const generateRefreshToken = async (user) => {
  if (!process.env.REFRESH_SECRET) {
    throw new Error("Missing REFRESH_SECRET in .env file");
  }
  const refreshToken = jwt.sign(
    { userId: user._id },
    process.env.REFRESH_SECRET,
    { expiresIn: "7d" }
  );

  user.refreshTokens.push(refreshToken);
  await user.save();

  return refreshToken;
};

// **Middleware to Verify Access Token**
const authenticateUser = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Unauthorized - No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ message: "Invalid or expired token" });
  }
};

// **🔹 User Authentication Routes**

// ✅ Register User
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields (username, email, password) are required." });
    }

    // duplicate credentials validation
    const existingUser = await User.findOne({ $or: [{username}, {email}] });
    if(existingUser){
      if (existingUser.username === username) return res.status(400).json({ message: "Username is already taken" });
      if (existingUser.email === email) return res.status(400).json({ message: "Email is already in use" });
    }

    // duplicate password validation
    const existingUsers = await User.find({});
    for (let user of existingUsers) {
      const isSamePassword = await bcrypt.compare(password, user.password);
      if (isSamePassword) {
        return res.status(400).json({ message: "This password has already been used" });
      }
    }

    // rest of code
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    const accessToken = generateAccessToken(newUser);
    const refreshToken = await generateRefreshToken(newUser);

    res.status(201).json({ message: "User registered", accessToken, refreshToken });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ✅ Login User
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if(!user) {
      return res.status(400).json({ message: "User with this email does not exists"});
    }
    if(!(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Invalid password"});
    }


    const accessToken = generateAccessToken(user);
    const refreshToken = await generateRefreshToken(user);

    res.json({ message: "Login successful", accessToken, refreshToken });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ✅ Refresh Access Token
app.post("/api/auth/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: "Unauthorized - No refresh token provided" });

    const user = await User.findOne({ refreshTokens: refreshToken });
    if (!user) return res.status(403).json({ message: "Invalid refresh token" });

    jwt.verify(refreshToken, process.env.REFRESH_SECRET, async (err, decoded) => {
      if (err) return res.status(403).json({ message: "Invalid refresh token" });

      const newAccessToken = generateAccessToken(user);
      res.json({ accessToken: newAccessToken });
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ✅ Logout (Single Device)
app.post("/api/auth/logout", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const user = await User.findOne({ refreshTokens: refreshToken });
    if (!user) return res.status(403).json({ message: "Invalid refresh token" });

    user.refreshTokens = user.refreshTokens.filter((token) => token !== refreshToken);
    await user.save();

    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ✅ Logout from All Devices
app.post("/api/auth/logout-all", authenticateUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    if (!user) return res.status(403).json({ message: "User not found" });

    user.refreshTokens = [];
    await user.save();

    res.status(200).json({ message: "Logged out from all devices" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// **🔹 Bookmark Routes (Protected)**
app.post("/api/bookmarks", authenticateUser, async (req, res) => {
  try {
    const newBookmark = new Bookmark({ ...req.body, userId: req.user.userId });
    await newBookmark.save();
    res.status(201).json(newBookmark);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/bookmarks", authenticateUser, async (req, res) => {
  try {
    const bookmarks = await Bookmark.find({ userId: req.user.userId }).sort({ createdAt: -1 });
    res.json(bookmarks);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.delete("/api/bookmarks/:id", authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const deletedBookmark = await Bookmark.findOneAndDelete({
      _id: id,
      userId: req.user.userId,
    });

    if (!deletedBookmark) {
      return res.status(404).json({ message: "Bookmark not found or unauthorized" });
    }

    res.json({ message: "Bookmark deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// **Start Server**
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
