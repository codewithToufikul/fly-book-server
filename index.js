const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const http = require("http");
const { Server } = require("socket.io");


const app = express();
const port = process.env.PORT || 5000;
// Middleware
app.use(cors());
app.use(express.json());

// MongoDB connection URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ivo4yuq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: false,
    deprecationErrors: true,
  },
});

// MongoDB connection
let isConnected = false;

async function connectToMongo() {
  if (isConnected) return;
  try {
    await client.connect();
    isConnected = true; // Set the flag
    console.log("MongoDB connected successfully.");
  } catch (error) {
    console.error("MongoDB connection error:", error);
  }
}


// Middleware to connect to MongoDB before every route
app.use(async (req, res, next) => {
  try {
    await connectToMongo();
    next();
  } catch (error) {
    console.error("MongoDB connection error:", error);
    res.status(500).send({ message: "Failed to connect to database" });
  }
});

const db = client.db("flybook");
const usersCollections = db.collection("usersCollections");
const opinionCollections = db.collection("opinionCollections");
const adminPostCollections = db.collection("adminPostCollections");
const bookCollections = db.collection("bookCollections");
const onindoBookCollections = db.collection("onindoBookCollections");
const bookTransCollections = db.collection("bookTransCollections");
const messagesCollections = db.collection("messagesCollections");
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";
// Create text index on opinions collection when the server starts
(async () => {
  try {
    await connectToMongo();
    await opinionCollections.createIndex({
      description: "text",
    });
    console.log("Text index created successfully!");
  } catch (error) {
    console.error("Error creating text index:", error);
  }
})();

// Route to check API status
app.get("/", (req, res) => {
  res.send("API is running!");
});

app.get("/search", async (req, res) => {
  try {
    const searchQuery = req.query.q;
    if (!searchQuery) {
      return res.status(400).json({ message: "Search query is required." });
    }

    const regex = new RegExp(searchQuery, "i"); // Case-insensitive search

    // Fetch matching results from each collection with different queries
    const users = await usersCollections
      .find(
        { name: regex },
        { projection: { name: 1, email: 1, number: 1, profileImage: 1 } }
      ) // শুধুমাত্র name এবং email আনবে
      .toArray();
    const opinionResults = await opinionCollections
      .find({
        $text: { $search: searchQuery },
      })
      .toArray();
    const bookResults = await bookCollections
      .find({ bookName: regex })
      .toArray();
    const onindoBookResults = await onindoBookCollections
      .find({ bookName: regex })
      .toArray();

    // Combine regex and text search results if needed
    const combinedResults = {
      users,
      opinions: opinionResults,
      books: bookResults,
      onindoBooks: onindoBookResults,
    };

    res.json(combinedResults);
  } catch (error) {
    console.error("Error in search:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// User Registration Route
app.post("/users/register", async (req, res) => {
  try {
    const { name, email, number, password } = req.body;

    // Check if user already exists
    const existingUser = await usersCollections.findOne({ number });
    if (existingUser) {
      return res.status(400).send({
        success: false,
        message: "User with this number already exists.",
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save the user to the database
    const newUser = {
      name,
      email,
      number,
      password: hashedPassword,
      verificationStatus: false,
      role: "user",
    };
    const result = await usersCollections.insertOne(newUser);

    res.send({
      success: true,
      message: "User registered successfully",
      data: result,
    });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).send({
      success: false,
      message: "An unexpected error occurred during registration.",
    });
  }
});

// User Login Route
app.post("/users/login", async (req, res) => {
  const { number, password } = req.body;

  try {
    const user = await usersCollections.findOne({ number });
    if (!user) {
      return res
        .status(401)
        .send({ success: false, message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res
        .status(401)
        .send({ success: false, message: "Invalid password" });
    }

    const token = jwt.sign({ id: user._id, number: user.number }, JWT_SECRET, {
      expiresIn: "1d",
    });
    res.json({ token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).send({ success: false, message: "Internal server error" });
  }
});

// Get profile information for the logged-in user
app.get("/profile", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      number: user.number,
      profileImage: user.profileImage,
      verificationStatus: user.verificationStatus,
      work: user.work,
      studies: user.studies,
      currentCity: user.currentCity,
      hometown: user.hometown,
      coverImage: user.coverImage,
      friendRequestsSent: user.friendRequestsSent,
      friendRequestsReceived: user.friendRequestsReceived,
      friends: user.friends,
      role: user.role,
    });
  } catch (error) {
    console.error("JWT Verification Error:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

// Update user's profile image URL
app.put("/profile/update", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const { profileImageUrl } = req.body;
    const updatedUser = await usersCollections.updateOne(
      { number: decoded.number },
      { $set: { profileImage: profileImageUrl } }
    );

    res.json({ message: "Profile updated successfully" });
  } catch (error) {
    console.error("JWT Verification Error:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.put("/profile/cover/update", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const { coverImageUrl } = req.body;
    const updatedUser = await usersCollections.updateOne(
      { number: decoded.number },
      { $set: { coverImage: coverImageUrl } }
    );

    res.json({ message: "Cover updated successfully" });
  } catch (error) {
    console.error("JWT Verification Error:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

// Update verification status
app.put("/profile/verification", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const { verificationStatus } = req.body;
    const updatedUser = await usersCollections.updateOne(
      { number: decoded.number },
      { $set: { verificationStatus } }
    );

    res.json({ message: "Verification status updated successfully" });
  } catch (error) {
    console.error("Error updating verification status:", error);
    res.status(500).json({ error: "Failed to update verification status." });
  }
});

app.put("/profile/updateDetails", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const { work, studies, currentCity, hometown, email } = req.body;

    const updatedUser = await usersCollections.updateOne(
      { number: decoded.number },
      { $set: { work, studies, currentCity, hometown, email } }
    );

    res.json({ message: "Profile updated successfully" });
  } catch (error) {
    console.error("Error updating profile details:", error);
    res.status(500).json({ error: "Failed to update profile details." });
  }
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const user = await usersCollections.findOne({ email: email });

  if (!user) {
    return res.status(404).json({ error: "User not found." });
  }
  const token = jwt.sign({ id: user._id }, "jwt_secret_key", {
    expiresIn: "1d",
  });
  var transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "flybook24@gmail.com",
      pass: "rswn cfdm lfpv arci",
    },
  });

  var mailOptions = {
    from: "flybook24@gmail.com",
    to: email,
    subject: "Your FlyBook Reset Password Link",
    text: `https://flybook-f23c5.web.app/reset_password/${user._id}/${token}`,
  };

  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      return res.send({ Status: "Success" });
    }
  });
});

// Reset Password - Update Password
app.post("/reset-password/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  const { password } = req.body;

  try {
    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update the user's password in the database
    const result = await usersCollections.updateOne(
      { _id: new ObjectId(id) },
      { $set: { password: hashedPassword } }
    );

    if (result.modifiedCount === 0) {
      return res.status(400).json({ error: "Failed to update password." });
    }

    res.json({ message: "Password updated successfully." });
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(400).json({ error: "Reset link expired." });
    }

    console.error("Error in reset-password route:", error);
    res.status(500).json({ error: "An unexpected error occurred." });
  }
});

// peoples api
// peoples api - Only return users excluding the logged-in user
app.get("/peoples", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    console.log("no token");
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Exclude the logged-in user and exclude passwords
    const result = await usersCollections
      .find(
        { number: { $ne: decoded.number } }, // Filter users excluding the logged-in user's number
        { projection: { password: 0 } } // Exclude the password field
      )
      .toArray();

    res.send(result);
  } catch (error) {
    console.error("Error fetching peoples:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.post("/friend-request/send", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { recipientId } = req.body;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const sender = await usersCollections.findOne({ number: decoded.number });

    if (!sender) {
      return res.status(404).json({ error: "Sender not found." });
    }

    const recipient = await usersCollections.findOne({
      _id: new ObjectId(recipientId),
    });

    if (!recipient) {
      return res.status(404).json({ error: "Recipient not found." });
    }

    // Prevent duplicate requests
    if (
      (recipient.friendRequestsReceived || []).includes(sender._id) ||
      (sender.friendRequestsSent || []).includes(recipientId)
    ) {
      return res.status(400).json({ error: "Friend request already sent." });
    }

    // Update both users
    await usersCollections.updateOne(
      { _id: new ObjectId(recipientId) },
      { $push: { friendRequestsReceived: sender._id } }
    );
    await usersCollections.updateOne(
      { number: sender.number },
      { $push: { friendRequestsSent: new ObjectId(recipientId) } }
    );

    res.json({ message: "Friend request sent successfully." });
  } catch (error) {
    console.error("Error sending friend request:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.get("/friend-request/received", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Populate friend request details
    const friendRequests = await usersCollections
      .find({ _id: { $in: user.friendRequestsReceived || [] } })
      .project({
        name: 1,
        profileImage: 1,
        email: 1,
        number: 1,
        currentCity: 1,
        hometown: 1,
        studies: 1,
        work: 1,
        coverImage: 1,
        friendRequestsSent: 1,
      })
      .toArray();

    res.json(friendRequests);
  } catch (error) {
    console.error("Error retrieving friend requests:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.post("/friend-request/accept", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { acceptId } = req.body;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    // Decode the JWT
    const decoded = jwt.verify(token, JWT_SECRET);
    const recipient = await usersCollections.findOne({
      number: decoded.number,
    });

    if (!recipient) {
      return res.status(404).json({ error: "Recipient not found." });
    }

    const sender = await usersCollections.findOne({
      _id: new ObjectId(acceptId),
    });

    if (!sender) {
      return res.status(404).json({ error: "Sender not found." });
    }

    console.log(
      "Recipient's friendRequestsReceived:",
      recipient.friendRequestsReceived
    );
    console.log("Sender ID:", sender._id);

    // Ensure the friend request exists
    const friendRequestExists = recipient.friendRequestsReceived?.some(
      (reqId) => reqId.toString() === sender._id.toString()
    );

    if (!friendRequestExists) {
      return res
        .status(400)
        .json({ error: "No friend request from this user." });
    }

    // Update recipient: Remove request and add to friends
    await usersCollections.updateOne(
      { _id: new ObjectId(recipient._id) },
      {
        $pull: { friendRequestsReceived: new ObjectId(sender._id) },
        $push: { friends: new ObjectId(sender._id) },
      }
    );

    // Update sender: Remove request and add to friends
    await usersCollections.updateOne(
      { _id: new ObjectId(sender._id) },
      {
        $pull: { friendRequestsSent: new ObjectId(recipient._id) },
        $push: { friends: new ObjectId(recipient._id) },
      }
    );

    res.json({ message: "Friend request accepted successfully." });
  } catch (error) {
    console.error("Error accepting friend request:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.post("/friend-request/reject", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { senderId } = req.body;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const recipient = await usersCollections.findOne({
      number: decoded.number,
    });

    await usersCollections.updateOne(
      { number: decoded.number },
      { $pull: { friendRequestsReceived: new ObjectId(senderId) } }
    );

    await usersCollections.updateOne(
      { _id: new ObjectId(senderId) },
      { $pull: { friendRequestsSent: new ObjectId(recipient._id) } }
    );

    res.json({ message: "Friend request rejected successfully." });
  } catch (error) {
    console.error("Error rejecting friend request:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.post("/friend-request/cancel", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { recipientId } = req.body;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const sender = await usersCollections.findOne({
      number: decoded.number,
    });

    await usersCollections.updateOne(
      { number: decoded.number },
      { $pull: { friendRequestsSent: new ObjectId(recipientId) } }
    );

    await usersCollections.updateOne(
      { _id: new ObjectId(recipientId) },
      { $pull: { friendRequestsReceived: new ObjectId(sender._id) } }
    );

    res.json({ message: "Friend request canceled successfully." });
  } catch (error) {
    console.error("Error canceling friend request:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.get("/friend-request/sended", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Populate friend request details
    const friendRequests = await usersCollections
      .find({ _id: { $in: user.friendRequestsSent || [] } })
      .project({
        name: 1,
        profileImage: 1,
        email: 1,
        number: 1,
        currentCity: 1,
        hometown: 1,
        studies: 1,
        work: 1,
        coverImage: 1,
        friendRequestsSent: 1,
      })
      .toArray();

    res.json(friendRequests);
  } catch (error) {
    console.error("Error retrieving friend requests:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.get("/all-friends", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const friends = await usersCollections
      .find({
        _id: { $in: user.friends },
      })
      .toArray();

    res.send(friends);
  } catch (error) {
    console.error("Error fetching peoples:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.post("/friend-request/unfriend", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { friendId } = req.body;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Find the friend in the database
    const friend = await usersCollections.findOne({
      _id: new ObjectId(friendId),
    });

    if (!friend) {
      return res.status(404).json({ error: "Friend not found." });
    }

    // Update user's friend list
    await usersCollections.updateOne(
      { _id: new ObjectId(user._id) },
      { $pull: { friends: new ObjectId(friendId) } }
    );

    // Update friend's friend list
    await usersCollections.updateOne(
      { _id: new ObjectId(friend._id) },
      { $pull: { friends: new ObjectId(user._id) } }
    );

    res.status(200).json({ message: "Unfriended successfully." });
  } catch (error) {
    console.error("Error in unfriend:", error);
    res.status(500).json({ error: "Something went wrong." });
  }
});

// post opinion rout
app.post("/opinion/post", async (req, res) => {
  const { postData } = req.body;
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    const newPost = {
      userId: user._id,
      userName: user.name,
      userProfileImage: user.profileImage,
      image: postData.image,
      description: postData.description,
      date: postData.date,
      time: postData.time,
      privacy: "public",
    };
    const result = await opinionCollections.insertOne(newPost);
    res.send({
      success: true,
      message: "User registered successfully",
      data: result,
    });
  } catch (error) {
    console.error("JWT Verification Error:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.get("/opinion/posts", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const posts = await opinionCollections.find().toArray();
    res.status(200).json({ success: true, data: posts });
  } catch (error) {
    console.error("Token validation error:", error.message || error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.post("/opinion/like", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    const { postId } = req.body;

    if (!postId) {
      return res.status(400).json({ error: "Post ID is required." });
    }

    // Find the post by ID
    const post = await opinionCollections.findOne({
      _id: new ObjectId(postId),
    });

    if (!post) {
      return res.status(404).json({ error: "Post not found." });
    }

    if (typeof post.likes !== "number") {
      await opinionCollections.updateOne(
        { _id: new ObjectId(postId) },
        { $set: { likes: parseInt(post.likes) || 0 } }
      );
    }
    console.log(user._id);
    const updatedPost = await opinionCollections.updateOne(
      { _id: new ObjectId(postId) },
      { $inc: { likes: 1 }, $push: { likedBy: user._id } }
    );

    if (updatedPost.modifiedCount === 0) {
      return res.status(500).json({ error: "Failed to like the post." });
    }

    res
      .status(200)
      .json({ success: true, message: "Post liked successfully." });
  } catch (error) {
    console.error("Error liking post:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.post("/opinion/unlike", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    const { postId } = req.body;

    if (!postId) {
      return res.status(400).json({ error: "Post ID is required." });
    }

    // Find the post by ID
    const post = await opinionCollections.findOne({
      _id: new ObjectId(postId),
    });

    if (!post) {
      return res.status(404).json({ error: "Post not found." });
    }

    const updatedPost = await opinionCollections.updateOne(
      { _id: new ObjectId(postId) },
      { $inc: { likes: -1 }, $pull: { likedBy: new ObjectId(user._id) } }
    );

    if (updatedPost.modifiedCount === 0) {
      return res.status(500).json({ error: "Failed to unlike the post." });
    }

    res
      .status(200)
      .json({ success: true, message: "Post unliked successfully." });
  } catch (error) {
    console.error("Error unliking post:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.post("/books/add", async (req, res) => {
  const { bookAllData } = req.body;
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    const bookData = {
      userId: bookAllData.userId,
      bookName: bookAllData.bookName,
      writer: bookAllData.writer,
      details: bookAllData.details,
      imageUrl: bookAllData.imageUrl,
      currentDate: bookAllData.currentDate,
      currentTime: bookAllData.currentTime,
      returnTime: bookAllData.returnTime,
      owner: currentUser.name,
    };
    const result = await bookCollections.insertOne(bookData);
    res.send({
      success: true,
      message: "Book Added successfully",
      data: result,
    });
  } catch (error) {
    console.error("JWT Verification Error:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.get("/all-books", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const books = await bookCollections.find().toArray();

    res.send(books);
  } catch (error) {
    console.error("Error fetching peoples:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.delete("/books/delete/:bookId", async (req, res) => {
  const { bookId } = req.params;
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await bookCollections.deleteOne({
      _id: new ObjectId(bookId),
    });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Book not found." });
    }

    res.send({
      success: true,
      message: "Book removed successfully",
      data: result,
    });
  } catch (error) {
    console.error("Error while deleting book:", error);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    res
      .status(500)
      .json({ error: "An error occurred while deleting the book." });
  }
});

app.post("/books/request", async (req, res) => {
  const { bookId } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  // Validate the token
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  // Validate bookId
  if (!bookId || !ObjectId.isValid(bookId)) {
    return res.status(400).json({ error: "Invalid or missing book ID." });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find the current user
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    // Check if the book exists
    const book = await bookCollections.findOne({ _id: new ObjectId(bookId) });
    if (!book) {
      return res.status(404).json({ error: "Book not found." });
    }

    // Update the book with request details
    const updateResult = await bookCollections.updateOne(
      { _id: new ObjectId(bookId) },
      {
        $set: {
          transfer: "pending",
          requestBy: currentUser._id,
          requestName: currentUser.name,
        },
      }
    );

    if (updateResult.modifiedCount === 0) {
      return res
        .status(400)
        .json({ error: "Failed to request the book. Try again later." });
    }

    // Respond with success
    res.status(200).json({ message: "Book request submitted successfully." });
  } catch (error) {
    console.error("Error while requesting book:", error);

    // Specific JWT error handling
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    // General error response
    res
      .status(500)
      .json({ error: "An error occurred while requesting the book." });
  }
});

app.post("/books/request/cancel", async (req, res) => {
  const { bookId } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  // Validate the token
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  // Validate bookId
  if (!bookId || !ObjectId.isValid(bookId)) {
    return res.status(400).json({ error: "Invalid or missing book ID." });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find the current user
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    // Check if the book exists
    const book = await bookCollections.findOne({ _id: new ObjectId(bookId) });
    if (!book) {
      return res.status(404).json({ error: "Book not found." });
    }

    // Update the book with request details
    const updateResult = await bookCollections.updateOne(
      { _id: new ObjectId(bookId) },
      {
        $set: { transfer: "no request", requestBy: "", requestName: "" },
      }
    );

    if (updateResult.modifiedCount === 0) {
      return res
        .status(400)
        .json({ error: "Failed to request the book. Try again later." });
    }

    // Respond with success
    res.status(200).json({ message: "Book request Canceled successfully." });
  } catch (error) {
    console.error("Error while canceling book:", error);

    // Specific JWT error handling
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    // General error response
    res
      .status(500)
      .json({ error: "An error occurred while canceling the book." });
  }
});

app.post("/books/request/accept", async (req, res) => {
  const { bookId, requestBy } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  // Validate the token
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  // Validate bookId
  if (!bookId || !ObjectId.isValid(bookId)) {
    return res.status(400).json({ error: "Invalid or missing book ID." });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find the current user
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    // Check if the book exists
    const book = await bookCollections.findOne({ _id: new ObjectId(bookId) });
    if (!book) {
      return res.status(404).json({ error: "Book not found." });
    }
    // Update the book with request details
    const updateResult = await bookCollections.updateOne(
      { _id: new ObjectId(bookId) },
      {
        $set: { transfer: "accept" },
      }
    );

    if (updateResult.modifiedCount === 0) {
      return res
        .status(400)
        .json({ error: "Failed to transfer the book. Try again later." });
    }

    // Respond with success
    res.status(200).json({ message: "Book request accept successfully." });
  } catch (error) {
    console.error("Error while canceling book:", error);

    // Specific JWT error handling
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    // General error response
    res
      .status(500)
      .json({ error: "An error occurred while accepting the book." });
  }
});

app.post("/books/request/trans", async (req, res) => {
  const { bookId, requestBy, requestName, date, time } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  // Validate the token
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  // Validate bookId
  if (!bookId || !ObjectId.isValid(bookId)) {
    return res.status(400).json({ error: "Invalid or missing book ID." });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find the current user
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    // Check if the book exists
    const book = await bookCollections.findOne({ _id: new ObjectId(bookId) });
    if (!book) {
      return res.status(404).json({ error: "Book not found." });
    }

    const transHistory = {
      sendId: currentUser._id,
      sendName: currentUser.name,
      bookImage: book.imageUrl,
      bookName: book.bookName,
      bookId: bookId,
      receiveId: requestBy,
      transName: requestName,
      transDate: date,
      transTime: time,
      transfer: "transfer",
    };
    // Update the book with request details
    const updateResult = await bookCollections.updateOne(
      { _id: new ObjectId(bookId) },
      {
        $set: { transfer: "success", transferTo: requestBy },
      }
    );
    if (updateResult.modifiedCount > 0) {
      await bookTransCollections.insertOne(transHistory);
    } else {
      return res
        .status(400)
        .json({ error: "Failed to transfer the book. Try again later." });
    }

    // Respond with success
    res.status(200).json({ message: "Book request accept successfully." });
  } catch (error) {
    console.error("Error while canceling book:", error);

    // Specific JWT error handling
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    // General error response
    res
      .status(500)
      .json({ error: "An error occurred while accepting the book." });
  }
});

app.get("/books/trans", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const posts = await bookTransCollections.find().toArray();
    res.status(200).json({ success: true, data: posts });
  } catch (error) {
    console.error("Token validation error:", error.message || error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.post("/books/return", async (req, res) => {
  const { bookId, requestBy, requestName, date, time, ownerId } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  // Validate the token
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  // Validate bookId
  if (!bookId || !ObjectId.isValid(bookId)) {
    return res.status(400).json({ error: "Invalid or missing book ID." });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find the current user
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    const receiveUser = await usersCollections.findOne({
      _id: new ObjectId(ownerId),
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    // Check if the book exists
    const book = await bookCollections.findOne({ _id: new ObjectId(bookId) });
    if (!book) {
      return res.status(404).json({ error: "Book not found." });
    }

    const transHistory = {
      sendId: requestBy,
      bookImage: book.imageUrl,
      bookName: book.bookName,
      bookId: bookId,
      receiveId: ownerId,
      receiveName: receiveUser.name,
      transName: requestName,
      transDate: date,
      transTime: time,
      return: "return",
    };
    // Update the book with request details
    const updateResult = await bookCollections.updateOne(
      { _id: new ObjectId(bookId) },
      {
        $set: {
          transfer: "no request",
          transferTo: "",
          requestBy: "",
          requestName: "",
        },
      }
    );
    if (updateResult.modifiedCount > 0) {
      await bookTransCollections.insertOne(transHistory);
    } else {
      return res
        .status(400)
        .json({ error: "Failed to transfer the book. Try again later." });
    }

    // Respond with success
    res.status(200).json({ message: "Book request accept successfully." });
  } catch (error) {
    console.error("Error while canceling book:", error);

    // Specific JWT error handling
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    // General error response
    res
      .status(500)
      .json({ error: "An error occurred while accepting the book." });
  }
});

app.post("/books/onindo/add", async (req, res) => {
  const { bookAllData } = req.body;
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    const bookData = {
      userId: bookAllData.userId,
      bookName: bookAllData.bookName,
      writer: bookAllData.writer,
      details: bookAllData.details,
      imageUrl: bookAllData.imageUrl,
      currentDate: bookAllData.currentDate,
      currentTime: bookAllData.currentTime,
      owner: currentUser.name,
    };
    const result = await onindoBookCollections.insertOne(bookData);
    res.send({
      success: true,
      message: "Book Added successfully",
      data: result,
    });
  } catch (error) {
    console.error("JWT Verification Error:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.get("/all-onindo-books", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const books = await onindoBookCollections.find().toArray();

    res.send(books);
  } catch (error) {
    console.error("Error fetching peoples:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.delete("/onindo/delete/:bookId", async (req, res) => {
  const { bookId } = req.params;
  console.log("hit");
  const token = req.headers.authorization?.split(" ")[1];
  console.log(token);
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await onindoBookCollections.deleteOne({
      _id: new ObjectId(bookId),
    });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Book not found." });
    }

    res.send({
      success: true,
      message: "Book removed successfully",
      data: result,
    });
  } catch (error) {
    console.error("Error while deleting book:", error);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    res
      .status(500)
      .json({ error: "An error occurred while deleting the book." });
  }
});

app.post("/onindo/books/request", async (req, res) => {
  const { bookId } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  // Validate the token
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  // Validate bookId
  if (!bookId || !ObjectId.isValid(bookId)) {
    return res.status(400).json({ error: "Invalid or missing book ID." });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find the current user
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    // Check if the book exists
    const book = await onindoBookCollections.findOne({
      _id: new ObjectId(bookId),
    });
    if (!book) {
      return res.status(404).json({ error: "Book not found." });
    }

    // Update the book with request details
    const updateResult = await onindoBookCollections.updateOne(
      { _id: new ObjectId(bookId) },
      {
        $set: {
          requestBy: currentUser._id,
          requestName: currentUser.name,
        },
      }
    );

    if (updateResult.modifiedCount === 0) {
      return res
        .status(400)
        .json({ error: "Failed to request the book. Try again later." });
    }

    // Respond with success
    res.status(200).json({ message: "Book request submitted successfully." });
  } catch (error) {
    console.error("Error while requesting book:", error);

    // Specific JWT error handling
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    // General error response
    res
      .status(500)
      .json({ error: "An error occurred while requesting the book." });
  }
});

app.post("/onindo/books/request/cancel", async (req, res) => {
  const { bookId } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  // Validate the token
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  // Validate bookId
  if (!bookId || !ObjectId.isValid(bookId)) {
    return res.status(400).json({ error: "Invalid or missing book ID." });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find the current user
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    // Check if the book exists
    const book = await onindoBookCollections.findOne({
      _id: new ObjectId(bookId),
    });
    if (!book) {
      return res.status(404).json({ error: "Book not found." });
    }

    // Update the book with request details
    const updateResult = await onindoBookCollections.updateOne(
      { _id: new ObjectId(bookId) },
      {
        $set: { requestBy: "", requestName: "" },
      }
    );

    if (updateResult.modifiedCount === 0) {
      return res
        .status(400)
        .json({ error: "Failed to request the book. Try again later." });
    }

    // Respond with success
    res.status(200).json({ message: "Book request Canceled successfully." });
  } catch (error) {
    console.error("Error while canceling book:", error);

    // Specific JWT error handling
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    // General error response
    res
      .status(500)
      .json({ error: "An error occurred while canceling the book." });
  }
});

app.post("/onindo/books/request/trans", async (req, res) => {
  const { bookId, requestBy, requestName, date, time } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  // Validate the token
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  // Validate bookId
  if (!bookId || !ObjectId.isValid(bookId)) {
    return res.status(400).json({ error: "Invalid or missing book ID." });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find the current user
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    // Check if the book exists
    const book = await onindoBookCollections.findOne({
      _id: new ObjectId(bookId),
    });
    if (!book) {
      return res.status(404).json({ error: "Book not found." });
    }

    const transHistory = {
      sendId: currentUser._id,
      bookImage: book.imageUrl,
      bookName: book.bookName,
      bookId: bookId,
      receiveId: requestBy,
      transName: requestName,
      transDate: date,
      transTime: time,
      sendName: currentUser.name,
    };
    // Update the book with request details
    const updateResult = await onindoBookCollections.updateOne(
      { _id: new ObjectId(bookId) },
      {
        $set: {
          transferTo: requestBy,
          userId: requestBy,
          requestBy: "",
          requestName: "",
        },
      }
    );
    if (updateResult.modifiedCount > 0) {
      await bookTransCollections.insertOne(transHistory);
    } else {
      return res
        .status(400)
        .json({ error: "Failed to transfer the book. Try again later." });
    }

    // Respond with success
    res.status(200).json({ message: "Book request accept successfully." });
  } catch (error) {
    console.error("Error while canceling book:", error);

    // Specific JWT error handling
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    // General error response
    res
      .status(500)
      .json({ error: "An error occurred while accepting the book." });
  }
});

app.delete("/user/delete/:userId", async (req, res) => {
  const { userId } = req.params;
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await usersCollections.deleteOne({
      _id: new ObjectId(userId),
    });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "user not found." });
    }

    res.send({
      success: true,
      message: "user removed successfully",
      data: result,
    });
  } catch (error) {
    console.error("Error while deleting user:", error);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    res
      .status(500)
      .json({ error: "An error occurred while deleting the book." });
  }
});

app.delete("/post/delete/:postId", async (req, res) => {
  const { postId } = req.params;
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await opinionCollections.deleteOne({
      _id: new ObjectId(postId),
    });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "post not found." });
    }

    res.send({
      success: true,
      message: "post removed successfully",
      data: result,
    });
  } catch (error) {
    console.error("Error while deleting user:", error);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    res
      .status(500)
      .json({ error: "An error occurred while deleting the book." });
  }
});

app.post("/admin/post", async (req, res) => {
  const { postData } = req.body;
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await adminPostCollections.insertOne(postData);
    res.send({
      success: true,
      message: "posted successfully",
      data: result,
    });
  } catch (error) {
    console.error("JWT Verification Error:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.get("/all-home-books", async (req, res) => {
  try {
    const post = await adminPostCollections.find().toArray();

    res.send(post);
  } catch (error) {
    console.error("Error fetching peoples:", error);
  }
});

app.post("/admin-post/like", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    const { postId } = req.body;

    if (!postId) {
      return res.status(400).json({ error: "Post ID is required." });
    }

    // Find the post by ID
    const post = await adminPostCollections.findOne({
      _id: new ObjectId(postId),
    });

    if (!post) {
      return res.status(404).json({ error: "Post not found." });
    }

    if (typeof post.likes !== "number") {
      await opinionCollections.updateOne(
        { _id: new ObjectId(postId) },
        { $set: { likes: parseInt(post.likes) || 0 } }
      );
    }

    const updatedPost = await adminPostCollections.updateOne(
      { _id: new ObjectId(postId) },
      { $inc: { likes: 1 }, $push: { likedBy: user._id } }
    );

    if (updatedPost.modifiedCount === 0) {
      return res.status(500).json({ error: "Failed to like the post." });
    }

    res
      .status(200)
      .json({ success: true, message: "Post liked successfully." });
  } catch (error) {
    console.error("Error liking post:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.post("/admin-post/unlike", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    const { postId } = req.body;

    if (!postId) {
      return res.status(400).json({ error: "Post ID is required." });
    }

    // Find the post by ID
    const post = await adminPostCollections.findOne({
      _id: new ObjectId(postId),
    });

    if (!post) {
      return res.status(404).json({ error: "Post not found." });
    }

    const updatedPost = await adminPostCollections.updateOne(
      { _id: new ObjectId(postId) },
      { $inc: { likes: -1 }, $pull: { likedBy: new ObjectId(user._id) } }
    );

    if (updatedPost.modifiedCount === 0) {
      return res.status(500).json({ error: "Failed to unlike the post." });
    }

    res
      .status(200)
      .json({ success: true, message: "Post unliked successfully." });
  } catch (error) {
    console.error("Error unliking post:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.post("/api/send-message", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { senderId, receoientId, messageText } = req.body;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res.status(404).json({ error: "User Not Found." });
    }

    const senderObjectId = ObjectId(senderId);
    const receoientObjectId = ObjectId(receoientId);
    const newMessage = {
      senderId: senderObjectId,
      receoientId: receoientObjectId,
      messageText: messageText,
      timestamp: new Date(),
    };
    const result = await messagesCollections.insertOne(newMessage);
    res.send({
      success: true,
      message: "posted successfully",
      data: result,
    });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.get("/api/chat-users", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    // Verify the JWT token and extract the user number
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Fetch chat history: Messages where the user is either the sender or receiver
    const chats = await messagesCollections.find({
      $or: [
        { senderId: ObjectId(user._id) },
        { receoientId: ObjectId(user._id) }
      ]
    }).toArray();

    if (chats.length === 0) {
      return res.status(404).json({ error: "No chat history found." });
    }

    // Extract unique user IDs from chat history
    const uniqueUserIds = [
      ...new Set(
        chats.map(msg => msg.senderId.toString() === user._id.toString() ? msg.receoientId.toString() : msg.senderId.toString())
      )
    ];

    // Fetch user details (name and profile image) for each unique user in chat history
    const chatUsers = await usersCollections.find({
      _id: { $in: uniqueUserIds.map(id => ObjectId(id)) }
    }).project({ name: 1, profileImage: 1 }).toArray();

    // Get the last message for each user
    const chatUsersWithLastMessage = await Promise.all(chatUsers.map(async (chatUser) => {
      const lastMessage = await messagesCollections.find({
        $or: [
          { senderId: ObjectId(user._id), receoientId: ObjectId(chatUser._id) },
          { senderId: ObjectId(chatUser._id), receoientId: ObjectId(user._id) }
        ]
      }).sort({ timestamp: -1 }).limit(1).toArray();

      return {
        ...chatUser,
        lastMessage: lastMessage[0] ? lastMessage[0].messageText : null,
        sender: lastMessage[0] ? (lastMessage[0].senderId.toString() === user._id.toString() ? 'You' : chatUser.name) : null,
      };
    }));

    res.send({ success: true, users: chatUsersWithLastMessage });
  } catch (error) {
    console.error("Error fetching chat users:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});


app.get("/api/messages/:userId", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = await usersCollections.findOne({ number: decoded.number });

    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    const { userId } = req.params;

    // Fetch chat messages where currentUser is either sender or receiver
    const messages = await messagesCollections
      .find({
        $or: [
          { senderId: ObjectId(currentUser._id), receoientId: ObjectId(userId) },
          { senderId: ObjectId(userId), receoientId: ObjectId(currentUser._id) }
        ]
      })
      .sort({ timestamp: 1 }) // Sort messages by timestamp
      .toArray();

    res.json({ success: true, messages });
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

const server = app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

const io = new Server(server, {
  cors: {
    origin: "https://flybook-f23c5.web.app", // আপনার ফ্রন্টএন্ডের পোর্ট
    methods: ["GET", "POST"],
    credentials: true, // Allow credentials if needed
  },
});

io.on("connection", (socket) => {
  console.log("New client connected");
  // ইউজারকে রুমে যোগ করা
  socket.on("joinRoom", (userId) => {
    const roomId = [userId].sort().join('-');
    socket.join(roomId); // ইউজারকে রুমে যোগ করা
    console.log('user join', roomId);
    socket.emit("connected");
  });

  socket.on("joinUser", (userId) => {
    const roomId = userId;
    socket.join(roomId); // ইউজারকে রুমে যোগ করা
    socket.emit("connected");
  });
  

  // মেসেজ পাঠানো
  socket.on("sendMessage", async (messageData) => {

    const { senderId, senderName, receoientId, messageText, roomId, messageType, mediaUrl } = messageData;
    try {
      // মেসেজ ডাটাবেসে সংরক্ষণ করা
      const newMessage = {
        senderId: ObjectId(senderId),
        receoientId: ObjectId(receoientId),
        messageText,
        messageType,
        mediaUrl,
        timestamp: new Date(),
      };

       
     await messagesCollections.insertOne(newMessage);

      // রিসিভেন্টের রুমে মেসেজ পাঠানো
      io.to(roomId).emit("receiveMessage", {
        senderId,
        messageText,
        messageType,
        mediaUrl,
        timestamp: new Date(),
      });

          // নোটিফিকেশন পাঠানো
    socket.to(receoientId).emit("newNotification", {
      senderName,
      senderId,
      messageText: messageText.substring(0, 30),
      timestamp: new Date(),
    });

    } catch (error) {
      console.error("Error sending message:", error);
    }
  });

  socket.on("typing", (data) => {
    socket.to(data.roomId).emit("typing", { senderId: data.senderId });
  });

  socket.on("disconnect", () => {
    console.log("A user disconnected:", socket.id); // ডিবাগিং
  });
});






// Start the serve



