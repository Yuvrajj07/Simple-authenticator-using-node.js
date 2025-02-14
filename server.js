const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
const PORT = 5000;
const SECRET_KEY = "your_secret_key"; // Change this to a strong secret key

// Middleware
app.use(cors());
app.use(express.json());  
app.use(bodyParser.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect("mongodb://127.0.0.1:27017/userDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log("✅ MongoDB Connected"))
.catch(err => console.log("❌ MongoDB Connection Error:", err));

// User Schema & Model
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    id: Number,
    password: String
});

const User = mongoose.model("User", userSchema);

// **🔹 User Registration API**
app.post("/register", async (req, res) => {
    try {
        const { name, email, id1, password } = req.body;

        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists!" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = new User({ name, email, id: id1, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: "User Registered Successfully!" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server Error" });
    }
});

// **🔹 User Login API**
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User not found!" });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid credentials!" });
        }

        // Generate JWT Token
        const token = jwt.sign({ userId: user._id, name: user.name }, SECRET_KEY, { expiresIn: "1h" });

        res.status(200).json({ message: "Login successful!", token, name: user.name });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server Error" });
    }
});

// **🔹 Protected Route (Example)**
app.get("/profile", verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select("-password");
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json({ user });
    } catch (error) {
        res.status(500).json({ message: "Server Error" });
    }
});

// **🔹 Middleware to Verify Token**
function verifyToken(req, res, next) {
    const token = req.header("Authorization");
    if (!token) {
        return res.status(403).json({ message: "Access Denied" });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ message: "Invalid Token" });
    }
}

// **Start Server**
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));