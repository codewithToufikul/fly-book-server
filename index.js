const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const multer = require("multer");
const { v2: cloudinary } = require("cloudinary");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const axios = require("axios");
const pdfParse = require("pdf-parse");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const http = require("http");
const { Server } = require("socket.io");
const { timeStamp } = require("console");
const { translate } = require("@vitalets/google-translate-api");

const app = express();
const port = process.env.PORT || 5000;
// Middleware
app.use(
  cors({
    origin: ["https://flybook.com.bd", "http://localhost:5173"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

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

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAMe,
  api_key: process.env.CLOUDINARY_API_KEy,
  api_secret: process.env.CLOUDINARY_API_SECREt,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: async (req, file) => {
    return {
      folder: "pdfBooks",
      resource_type: file.mimetype === "application/pdf" ? "raw" : "image",
      format: file.mimetype === "application/pdf" ? "pdf" : undefined,
      public_id: file.originalname.replace(/\.[^/.]+$/, ""),
    };
  },
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit
  },
});

const getPdfPageCount = async (pdfUrl) => {
  try {
    const response = await axios.get(pdfUrl, { responseType: "arraybuffer" });
    const data = await pdfParse(response.data);
    return data.numpages;
  } catch (error) {
    return null;
  }
};

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
const adminThesisCollections = db.collection("adminThesisCollections");
const bookCollections = db.collection("bookCollections");

const onindoBookCollections = db.collection("onindoBookCollections");
const bookTransCollections = db.collection("bookTransCollections");
const messagesCollections = db.collection("messagesCollections");
const pdfCollections = db.collection("pdfCollections");
const notifyCollections = db.collection("notifyCollections");
const noteCollections = db.collection("noteCollections");
const organizationCollections = db.collection("organizationCollections");
const homeCategoryCollection = db.collection("homeCategoryCollection");
const adminAiPostCollections = db.collection("adminAiPostCollections");
const JWT_SECRET = process.env.ACCESS_TOKEN_SECRET;
const channelsCollection = db.collection("Channels");
const channelessagesCollection = db.collection("channelMessages");
const coursesCollection = db.collection("coursesCollection");
const sellerCollections = db.collection("sellerCollections");
const productsCollection = db.collection("productsCollection");
const productsCategories = db.collection("productsCategories");
const cartsCollection = db.collection("cartsCollection");
const ordersCollection = db.collection("ordersCollection");
const addressesCollection = db.collection("addressesCollection");
const withdrawsCollection = db.collection("withdrawsCollection");
const bannersCollection = db.collection("bannersCollection");
// Create text index on opinions collection when the server starts

const HUGGING_FACE_API_KEY = process.env.HUGGING_FACE_API_KEY;
const GOOGLE_API_KEY = process.env.GOOGLE_CUSTOM_SEARCH_API_KEY;
const SEARCH_ENGINE_ID = process.env.GOOGLE_CUSTOM_SEARCH_ENGINE_ID;
const GMINI_API_KEY = process.env.GMINI_API_KEY;

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
(async () => {
  try {
    await connectToMongo();
    await bookCollections.createIndex({ location: "2dsphere" });
    console.log("location index created successfully!");
  } catch (error) {
    console.error("Error creating location index:", error);
  }
})();

// Route to check API status
app.get("/", (req, res) => {
  res.send("API is running!");
});

app.post("/api/translate", async (req, res) => {
  const { text, targetLang } = req.body;

  try {
    const { text: translatedText } = await translate(text, { to: targetLang });
    console.log(targetLang);
    res.json({ translation: translatedText });
  } catch (error) {
    console.error("Translation Error:", error);
    res.status(500).json({ error: "Translation failed!" });
  }
});

// Combined search endpoint that matches the frontend implementation
app.get("/search", async (req, res) => {
  try {
    const searchQuery = req.query.q;
    if (!searchQuery) {
      return res.status(400).json({ message: "Search query is required." });
    }
    const regex = new RegExp(searchQuery, "i");
    let websiteResults = {};
    let aiResult = "No AI result found";
    // ✅ Fetch AI-generated result from Hugging Face
    try {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${process.env.GMINI_API_KEY}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            contents: [
              {
                parts: [
                  {
                    text: `Define in 2-3 brief sentences: ${searchQuery}`,
                  },
                ],
              },
            ],
          }),
        }
      );

      // Check if the response is JSON
      const contentType = response.headers.get("Content-Type");
      if (contentType && contentType.includes("application/json")) {
        const data = await response.json(); // Parse the response JSON

        if (
          data &&
          data.candidates &&
          data.candidates[0] &&
          data.candidates[0].content &&
          data.candidates[0].content.parts &&
          data.candidates[0].content.parts[0] &&
          data.candidates[0].content.parts[0].text
        ) {
          aiResult = data.candidates[0].content.parts[0].text; // Extract response text
        } else if (data.error) {
          console.error("Gemini API Error:", data.error);
          aiResult = "Failed to fetch AI result. Please try again later.";
        } else {
          aiResult = "No response from AI.";
        }
      } else {
        const errorText = await response.text(); // Read error response
        console.error("Error from Gemini API:", errorText);
        aiResult = "Failed to fetch AI result. Please try again later.";
      }
    } catch (error) {
      console.error("Gemini API Error:", error);
      aiResult = "No AI result found"; // Fallback message
    }

    // ✅ Fetch website users
    try {
      const users = await usersCollections
        .find(
          { $or: [{ name: regex }, { userName: regex }] },
          {
            projection: {
              name: 1,
              email: 1,
              number: 1,
              profileImage: 1,
              userName: 1,
            },
          }
        )
        .toArray();
      websiteResults.users = users || [];
    } catch (error) {
      console.error("Error fetching users:", error);
      websiteResults.users = [];
    }

    // ✅ Fetch opinions (text search + regex search)
    try {
      const textSearchResults = await opinionCollections
        .find({ $text: { $search: searchQuery } })
        .toArray();
      const regexSearchResults = await opinionCollections
        .find({ userName: regex })
        .toArray();
      websiteResults.opinions = [...textSearchResults, ...regexSearchResults];
    } catch (error) {
      console.error("Error fetching opinions:", error);
      websiteResults.opinions = [];
    }

    // ✅ Fetch books
    try {
      const bookResults = await bookCollections
        .find({ $or: [{ bookName: regex }, { owner: regex }] })
        .toArray();
      websiteResults.books = bookResults || [];
    } catch (error) {
      console.error("Error fetching books:", error);
      websiteResults.books = [];
    }

    // ✅ Fetch PDF books
    try {
      const pdfBookResults = await pdfCollections
        .find({ $or: [{ bookName: regex }, { writerName: regex }] })
        .toArray();
      websiteResults.pdfBooks = pdfBookResults || [];
    } catch (error) {
      console.error("Error fetching PDF books:", error);
      websiteResults.pdfBooks = [];
    }

    // ✅ Google Custom Search results
    let googleResults = { items: [] };
    if (GOOGLE_API_KEY && SEARCH_ENGINE_ID) {
      try {
        const googleSearchUrl = `https://www.googleapis.com/customsearch/v1?key=${GOOGLE_API_KEY}&cx=${SEARCH_ENGINE_ID}&q=${encodeURIComponent(
          searchQuery
        )}&num=5&safe=active`;

        const response = await fetch(googleSearchUrl);
        const googleData = await response.json();
        googleResults = googleData.items ? googleData : { items: [] };
      } catch (error) {
        console.error("Error in Google search:", error);
      }
    }

    // ✅ Send the final response
    res.json({
      aiResult,
      websiteResults,
      googleResults,
    });
  } catch (error) {
    console.error("Error in search:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// User Registration Route
app.post("/users/register", async (req, res) => {
  try {
    const { name, email, number, password, userLocation } = req.body;
    console.log(userLocation)
    // Check if user already exists
    const existingUser = await usersCollections.findOne({ number });
    if (existingUser) {
      return res.status(400).send({
        success: false,
        message: "User with this number already exists.",
      });
    }

    // Generate username from name
    const baseName = name.toLowerCase().replace(/\s+/g, "");
    let username = baseName;
    let counter = 1;

    // Keep checking and incrementing counter until we find a unique username
    while (await usersCollections.findOne({ userName: username })) {
      username = `${baseName}${Math.floor(Math.random() * 1000)}`;
      counter++;
      if (counter > 10) {
        // Prevent infinite loop, add timestamp if needed
        username = `${baseName}${Date.now()}`;
        break;
      }
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save the user to the database
    const newUser = {
      name,
      email,
      number,
      userName: username,
      password: hashedPassword,
      verificationStatus: false,
      userLocation: {
        type: "Point",
        coordinates: [
          parseFloat(userLocation.longitude),
          parseFloat(userLocation.latitude),
        ],
      },
      role: "user",
      profileImage:
        "https://i.ibb.co/mcL9L2t/f10ff70a7155e5ab666bcdd1b45b726d.jpg",
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

  // Input validation
  if (!number || !password) {
    return res
      .status(400)
      .json({ success: false, message: "Number and password are required" });
  }

  try {
    const user = await usersCollections.findOne({ number });

    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid number or password" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid number or password" });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        id: user._id.toString(),
        number: user.number,
      },
      JWT_SECRET, // Always keep secret in env variables
      {
        expiresIn: "30d", // human-readable format
      }
    );
    // Respond with token and basic user info (never password!)
    res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user._id,
        number: user.number,
        name: user.name,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
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
    if (!decoded.number) {
      return res.status(400).json({ error: "Invalid token payload." });
    }

    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json({
      id: user._id,
      name: user.name,
      userName: user.userName,
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
    console.error("JWT Verification Error:", error.message);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

// Upload PDF book endpoint
app.post("/upload", async (req, res) => {
  try {
    const {
      bookName,
      writerName,
      category,
      uploadMethod,
      description,
      pdfUrl,
      coverUrl,
      pageCount,
      fileSize,
    } = req.body;

    // Validate required fields
    if (!bookName || !writerName || !category || !pdfUrl || !coverUrl) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields",
      });
    }

    // Create new PDF book document
    const newPdfBook = {
      bookName,
      writerName,
      category,
      uploadMethod,
      description,
      pdfUrl,
      coverUrl,
      pageCount,
      fileSize,
      timestamp: new Date(), // Using createdAt is more standard than timestamp
    };

    const result = await pdfCollections.insertOne(newPdfBook);

    if (result.acknowledged) {
      res.status(201).json({
        success: true,
        message: "PDF book uploaded successfully",
        bookId: result.insertedId,
      });
    } else {
      res.status(400).json({
        success: false,
        message: "Failed to upload PDF book",
      });
    }
  } catch (error) {
    console.error("Error uploading PDF book:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

app.get("/pdf-books", async (req, res) => {
  try {
    const books = await pdfCollections.find().toArray();
    res.status(200).json(books);
  } catch (error) {
    res.status(500).json({ message: "Server Error", error });
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

app.get("/users/nearby", async (req, res) => {
  const { longitude, latitude, maxDistance = 4000 } = req.query;

  try {
    const nearbyUsers = await usersCollections
      .aggregate([
        {
          $geoNear: {
            near: {
              type: "Point",
              coordinates: [parseFloat(longitude), parseFloat(latitude)],
            },
            distanceField: "distance",
            maxDistance: parseFloat(maxDistance),
            spherical: true,
          },
        },
        {
          $project: {
            _id: 1, // _id ফিল্ড শো করবে
            name: 1, // নাম ফিল্ড
            profileImage: 1, // প্রোফাইল ইমেজ
            // অন্যান্য ফিল্ড অটোমেটিকালি এক্সক্লুড হবে
          },
        },
      ])
      .toArray();

    res.send({
      success: true,
      data: nearbyUsers,
    });
    console.log(nearbyUsers);
  } catch (error) {
    console.error("Error fetching nearby users:", error);
    res.status(500).send({
      success: false,
      message: "An unexpected error occurred.",
    });
  }
});

app.put("/profile/updateDetails/location", async (req, res) => {
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

    const { userLocation } = req.body;

    const updatedUser = await usersCollections.updateOne(
      { number: decoded.number },
      {
        $set: {
          userLocation: {
            type: "Point",
            coordinates: [
              parseFloat(userLocation.longitude),
              parseFloat(userLocation.latitude),
            ],
          },
        },
      }
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
  const token = jwt.sign({ id: user._id }, JWT_SECRET, {
    expiresIn: "30d",
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
    text: `https://flybook.com.bd/reset_password/${user._id}/${token}`,
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
app.get("/thesis", async (req, res) => {
  try {
    // Exclude the logged-in user and exclude passwords
    const result = await adminThesisCollections.find().toArray();

    res.send(result);
  } catch (error) {
    console.error("Error fetching thesis:", error);
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

    // Check if friends array exists, otherwise use empty array
    const friendsIds = user.friends || [];

    const friends = await usersCollections
      .find({
        _id: { $in: friendsIds },
      })
      .toArray();

    res.send(friends);
  } catch (error) {
    console.error("Error fetching friends:", error);
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
      pdf: postData.pdf,
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

app.get("/opinion/posts/:id", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid post ID." });
    }

    const post = await opinionCollections.findOne({ _id: new ObjectId(id) });

    if (!post) {
      return res.status(404).json({ error: "Post not found." });
    }

    res.status(200).json({ success: true, data: post });
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
      location: bookAllData.location,
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
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }
    if (currentUser.role !== "admin") {
      return res
        .status(403)
        .json({ error: "Access denied. You are not an admin." });
    }

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
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }
    if (currentUser.role !== "admin") {
      return res
        .status(403)
        .json({ error: "Access denied. You are not an admin." });
    }
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
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }
    if (currentUser.role !== "admin") {
      return res
        .status(403)
        .json({ error: "Access denied. You are not an admin." });
    }
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
app.post("/admin/thesis", async (req, res) => {
  const { postData } = req.body;
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }
    if (currentUser.role !== "admin") {
      return res
        .status(403)
        .json({ error: "Access denied. You are not an admin." });
    }
    const result = await adminThesisCollections.insertOne(postData);
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

app.post("/admin/post-ai", async (req, res) => {
  const { postData } = req.body;
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }
    if (currentUser.role !== "admin") {
      return res
        .status(403)
        .json({ error: "Access denied. You are not an admin." });
    }
    const result = await adminAiPostCollections.insertOne(postData);
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

app.get("/admin/post-ai", async (req, res) => {
  try {
    // Exclude the logged-in user and exclude passwords
    const result = await adminAiPostCollections.find().toArray();

    res.send(result);
  } catch (error) {
    console.error("Error fetching ai post:", error);
  }
});

app.get("/admin/post-ai/:postId", async (req, res) => {
  const { postId } = req.params;
  try {
    const result = await adminAiPostCollections.findOne({
      _id: new ObjectId(postId),
    });
    res.send(result);
  } catch (error) {
    console.error("Error fetching ai post:", error);
  }
});

app.delete("/admin/post-ai/:id", async (req, res) => {
  const { id } = req.params;
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });

    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    if (currentUser.role !== "admin") {
      return res
        .status(403)
        .json({ error: "Access denied. You are not an admin." });
    }

    const result = await adminAiPostCollections.deleteOne({
      _id: new ObjectId(id),
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: "Post not found." });
    }

    res.json({ message: "Post deleted successfully" });
  } catch (error) {
    console.error("Error deleting post:", error);
    res.status(500).json({ error: "Failed to delete post" });
  }
});

app.put("/admin/post-ai/:id", async (req, res) => {
  const { id } = req.params;
  const { postData } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });

    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    if (currentUser.role !== "admin") {
      return res
        .status(403)
        .json({ error: "Access denied. You are not an admin." });
    }

    const result = await adminAiPostCollections.updateOne(
      { _id: new ObjectId(id) },
      { $set: postData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: "Post not found." });
    }

    res.json({ message: "Post updated successfully" });
  } catch (error) {
    console.error("Error updating post:", error);
    res.status(500).json({ error: "Failed to update post" });
  }
});

app.get("/all-home-books", async (req, res) => {
  try {
    const { category } = req.query;
    let query = {};

    if (category && category !== "All") {
      query.category = category;
    }

    const post = await adminPostCollections.find(query).toArray();
    res.send(post);
  } catch (error) {
    console.error("Error fetching posts:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/all-home-post/:id", async (req, res) => {
  const id = req.params.id;
  console.log("Fetching post with ID:", id); // Debug log
  try {
    const post = await adminPostCollections.findOne({ _id: new ObjectId(id) });
    res.send(post);
  } catch (error) {
    console.error("Error fetching post:", error);
    res.status(500).json({ error: error.message });
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

app.post("/admin-post/comment", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    const { postId, comment } = req.body;

    if (!postId || !comment?.trim()) {
      return res
        .status(400)
        .json({ error: "Post ID and comment are required." });
    }

    const postObjectId = new ObjectId(postId);
    const post = await adminPostCollections.findOne({ _id: postObjectId });

    if (!post) {
      return res.status(404).json({ error: "Post not found." });
    }

    const commentObj = {
      id: Date.now(), // unique ID for frontend tracking
      comment: comment.trim(),
      userId: user._id,
      userName: user.name || user.number,
      userPhoto: user.profileImage || null,
      createdAt: new Date().toISOString(),
    };

    const result = await adminPostCollections.updateOne(
      { _id: postObjectId },
      { $push: { comments: { $each: [commentObj], $position: 0 } } } // add to top
    );

    if (result.modifiedCount === 0) {
      return res.status(500).json({ error: "Failed to add comment." });
    }

    res.status(200).json({
      success: true,
      message: "Comment added successfully.",
      comment: commentObj,
    });
  } catch (error) {
    console.error("Error submitting comment:", error);
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

app.post("/admin-post/unlike", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  console.log(token);
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    const { postId } = req.body;
    console.log(postId);
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

app.delete("/api/delete-message/:messageId", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { messageId } = req.params;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res.status(404).json({ error: "User Not Found." });
    }

    // Delete the message from the database
    const result = await messagesCollections.deleteOne({
      _id: ObjectId(messageId),
      $or: [{ senderId: user._id }, { receoientId: user._id }],
    });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ error: "Message not found or access denied." });
    }

    res.send({
      success: true,
      message: "Message deleted successfully.",
    });
  } catch (error) {
    console.error("Error deleting message:", error);
    res.status(500).json({ error: "Failed to delete the message." });
  }
});
app.delete("/api/delete-conversation/:messageId", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { messageId } = req.params;
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res.status(404).json({ error: "User Not Found." });
    }

    // Convert messageId to ObjectId
    const targetUserId = new ObjectId(messageId);

    // Delete conversation query with proper ObjectId conversion
    const result = await messagesCollections.deleteMany({
      $or: [
        { senderId: targetUserId, receoientId: user._id },
        { senderId: user._id, receoientId: targetUserId },
      ],
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: "No messages found to delete." });
    }

    res.send({
      success: true,
      message: "Conversation deleted successfully.",
    });
  } catch (error) {
    console.error("Error deleting conversation:", error);
    if (error.name === "BSONTypeError") {
      return res.status(400).json({ error: "Invalid message ID format" });
    }
    res.status(500).json({ error: "Failed to delete the conversation." });
  }
});

app.get("/api/chat-users", async (req, res) => {
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

    // Fetch chat history with proper ObjectId conversion and null checks
    const chats = await messagesCollections
      .find({
        $or: [
          { senderId: new ObjectId(user._id) },
          { receoientId: new ObjectId(user._id) },
        ],
      })
      .toArray();

    // If no chats found, return empty array instead of 404
    if (!chats || chats.length === 0) {
      return res.json({ success: true, users: [] });
    }

    // Safely extract unique user IDs with null checks
    const uniqueUserIds = [
      ...new Set(
        chats.reduce((ids, msg) => {
          if (msg.senderId && msg.receoientId) {
            const senderId = msg.senderId.toString();
            const receoientId = msg.receoientId.toString();
            const userId =
              senderId === user._id.toString() ? receoientId : senderId;
            if (userId) ids.push(userId);
          }
          return ids;
        }, [])
      ),
    ];

    // Fetch user details for valid IDs
    const chatUsers = await usersCollections
      .find({
        _id: {
          $in: uniqueUserIds
            .map((id) => {
              try {
                return new ObjectId(id);
              } catch (e) {
                return null;
              }
            })
            .filter((id) => id !== null),
        },
      })
      .project({ name: 1, profileImage: 1 })
      .toArray();

    // Get last message for each user with error handling
    const chatUsersWithLastMessage = await Promise.all(
      chatUsers.map(async (chatUser) => {
        try {
          const lastMessage = await messagesCollections
            .find({
              $or: [
                {
                  senderId: new ObjectId(user._id),
                  receoientId: new ObjectId(chatUser._id),
                },
                {
                  senderId: new ObjectId(chatUser._id),
                  receoientId: new ObjectId(user._id),
                },
              ],
            })
            .sort({ timestamp: -1 })
            .limit(1)
            .toArray();

          return {
            ...chatUser,
            lastMessage: lastMessage[0]?.messageText || null,
            sender: lastMessage[0]
              ? lastMessage[0].senderId.toString() === user._id.toString()
                ? "You"
                : chatUser.name
              : null,
          };
        } catch (error) {
          console.error(`Error processing chat user ${chatUser._id}:`, error);
          return {
            ...chatUser,
            lastMessage: null,
            sender: null,
          };
        }
      })
    );

    res.json({ success: true, users: chatUsersWithLastMessage });
  } catch (error) {
    console.error("Error fetching chat users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/messages/:userId", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });

    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    const { userId } = req.params;

    // Fetch chat messages where currentUser is either sender or receiver
    const messages = await messagesCollections
      .find({
        $or: [
          {
            senderId: ObjectId(currentUser._id),
            receoientId: ObjectId(userId),
          },
          {
            senderId: ObjectId(userId),
            receoientId: ObjectId(currentUser._id),
          },
        ],
      })
      .sort({ timestamp: 1 }) // Sort messages by timestamp
      .toArray();

    res.json({ success: true, messages });
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.get("/api/notifications/:userId", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });

    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    const { userId } = req.params;
    console.log("userid", userId);
    // Fetch chat messages where currentUser is either sender or receiver
    const notifications = await notifyCollections
      .find({ receoientId: new ObjectId(userId) })
      .toArray();

    res.json({ success: true, notifications });
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.delete("/admin-post-delete/:postId", async (req, res) => {
  const { postId } = req.params;
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (user.role !== "admin") {
      return res
        .status(404)
        .json({ success: false, message: "Unathorized access !" });
    }
    const result = await adminPostCollections.deleteOne({
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

app.delete("/admin/category-delete/:categoryId", async (req, res) => {
  const { categoryId } = req.params;
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (user.role !== "admin") {
      return res
        .status(403)
        .json({ success: false, message: "Unauthorized access!" });
    }

    const result = await homeCategoryCollection.deleteOne({
      _id: new ObjectId(categoryId),
    });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Category not found." });
    }

    res.status(200).json({
      success: true,
      message: "Category deleted successfully",
    });
  } catch (error) {
    console.error("Error while deleting category:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/admin/category-update/:categoryId", async (req, res) => {
  const { categoryId } = req.params;
  const { category } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (user.role !== "admin") {
      return res
        .status(403)
        .json({ success: false, message: "Unauthorized access!" });
    }

    const result = await homeCategoryCollection.updateOne(
      { _id: new ObjectId(categoryId) },
      { $set: { category } }
    );

    if (result.matchedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Category not found." });
    }

    res.status(200).json({
      success: true,
      message: "Category updated successfully",
    });
  } catch (error) {
    console.error("Error while updating category:", error);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/admin-post-edit/:postId", async (req, res) => {
  const { postId } = req.params;
  const { title, message } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (user.role !== "admin") {
      return res
        .status(403)
        .json({ success: false, message: "Unauthorized access!" });
    }

    const updatedPost = await adminPostCollections.updateOne(
      { _id: new ObjectId(postId) },
      { $set: { title, message, updatedAt: new Date() } }
    );

    if (updatedPost.matchedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Post not found." });
    }

    res.send({
      success: true,
      message: "Post updated successfully.",
      data: updatedPost,
    });
  } catch (error) {
    console.error("Error while updating post:", error);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    res
      .status(500)
      .json({ error: "An error occurred while updating the post." });
  }
});

app.post("/admin/category-add", async (req, res) => {
  const { category } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (user.role !== "admin") {
      return res
        .status(403)
        .json({ success: false, message: "Unauthorized access!" });
    }
    const categoryItem = {
      category,
    };
    await homeCategoryCollection.insertOne(categoryItem);

    res.send({
      success: true,
      message: "category added successfully.",
    });
  } catch (error) {
    console.error("Error while adding category:", error);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    res.status(500).json({ error: "An error occurred while adding category" });
  }
});

app.get("/home-category", async (req, res) => {
  try {
    const categories = await homeCategoryCollection.find().toArray();
    res.json({ success: true, categories });
  } catch (error) {
    console.error("Error while getting category:", error);
    res.status(500).json({ error: "An error occurred while getting category" });
  }
});

app.put("/pdf-books/:id", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { id } = req.params;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (user.role !== "admin") {
      return res
        .status(403)
        .json({ success: false, message: "Unauthorized access!" });
    }

    const { bookName, writerName, category, pdfUrl, coverUrl, description } =
      req.body;

    const updatedBook = await pdfCollections.findOneAndUpdate(
      { _id: new ObjectId(id) },
      {
        $set: {
          bookName,
          writerName,
          category,
          pdfUrl,
          coverUrl,
          description,
          updatedAt: new Date(),
        },
      },
      { returnDocument: "after" }
    );

    if (!updatedBook.value) {
      return res
        .status(404)
        .json({ success: false, message: "Book not found" });
    }

    res.json({
      success: true,
      message: "Book updated successfully",
      book: updatedBook.value,
    });
  } catch (error) {
    console.error("Error updating book:", error);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    res
      .status(500)
      .json({ error: "An error occurred while updating the book" });
  }
});

app.delete("/pdf-books/:id", async (req, res) => {
  const { id } = req.params;
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (user.role !== "admin") {
      return res
        .status(403)
        .json({ success: false, message: "Unauthorized access!" });
    }

    const result = await pdfCollections.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Book not found" });
    }

    res.json({ success: true, message: "Book deleted successfully" });
  } catch (error) {
    console.error("Error deleting book:", error);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    res
      .status(500)
      .json({ error: "An error occurred while deleting the book" });
  }
});

app.post("/notes/add", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { content } = req.body;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const newNote = {
      userId: user._id,
      content: content,
      createdAt: new Date(),
    };

    const result = await noteCollections.insertOne(newNote);

    if (!result.insertedId) {
      return res
        .status(500)
        .json({ success: false, error: "Failed to add note" });
    }

    res.status(200).json({
      success: true,
      note: {
        _id: result.insertedId,
        ...newNote,
      },
    });
  } catch (error) {
    console.error("Error adding note:", error);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    res.status(500).json({ error: "An error occurred while adding the note" });
  }
});

app.get("/notes", async (req, res) => {
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

    const notes = await noteCollections
      .find({ userId: user._id })
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json({
      success: true,
      notes: notes,
    });
  } catch (error) {
    console.error("Error fetching notes:", error);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    res.status(500).json({ error: "An error occurred while fetching notes" });
  }
});

app.delete("/notes/:noteId", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { noteId } = req.params;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const result = await noteCollections.deleteOne({
      _id: new ObjectId(noteId),
      userId: user._id,
    });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ error: "Note not found or access denied." });
    }

    res.status(200).json({
      success: true,
      message: "Note deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting note:", error);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    res
      .status(500)
      .json({ error: "An error occurred while deleting the note" });
  }
});

// Add organization endpoint
app.post("/add-organizations", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res.status(403).json({
        error: "Unauthorized access. Only admins can add organizations.",
      });
    }
    const {
      orgName,
      email,
      phone,
      website,
      address,
      description,
      profileImage,
    } = req.body;

    // Validate required fields
    if (
      !orgName ||
      !email ||
      !phone ||
      !address ||
      !description ||
      !profileImage
    ) {
      return res.status(400).json({
        success: false,
        message: "Please provide all required fields",
      });
    }

    // Get current date and time
    const currentDate = new Date();
    const postDate = currentDate.toLocaleDateString();
    const postTime = currentDate.toLocaleTimeString();

    // Create organization document
    const organization = {
      postBy: user._id,
      postByName: user.name,
      postByProfile: user.profileImage,
      orgName,
      email,
      phone,
      website,
      address,
      description,
      profileImage,
      status: "pending",
      postDate,
      postTime,
      createdAt: currentDate,
    };

    // Insert into database
    const result = await organizationCollections.insertOne(organization);

    if (!result.acknowledged) {
      return res.status(400).json({
        success: false,
        message: "Failed to add organization",
      });
    }

    res.status(200).json({
      success: true,
      message: "Organization added successfully",
      data: result,
    });
  } catch (error) {
    console.error("Error adding organization:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred while adding the organization",
    });
  }
});

// Get all organizations
app.get("/api/v1/organizations", async (req, res) => {
  try {
    const organizations = await organizationCollections
      .find({ status: { $eq: "pending" } })
      .toArray();

    res.status(200).json({
      success: true,
      message: "Organizations retrieved successfully",
      data: organizations,
    });
  } catch (error) {
    console.error("Error retrieving organizations:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred while retrieving organizations",
    });
  }
});

app.get("/api/v1/organizations/aprooved", async (req, res) => {
  try {
    const organizations = await organizationCollections
      .find({ status: { $eq: "accepted" } })
      .toArray();

    res.status(200).json({
      success: true,
      message: "Organizations retrieved successfully",
      data: organizations,
    });
  } catch (error) {
    console.error("Error retrieving organizations:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred while retrieving organizations",
    });
  }
});

// ... existing code ...

// Approve organization endpoint
app.patch("/api/v1/organizations/:id/approve", async (req, res) => {
  const { orgType } = req.body;
  console.log(orgType);
  const token = req.headers.authorization?.split(" ")[1];
  const { id } = req.params;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user || user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Unauthorized. Only admins can approve organizations.",
      });
    }

    const result = await organizationCollections.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status: "accepted", orgType: orgType } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Organization not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Organization approved successfully",
    });
  } catch (error) {
    console.error("Error approving organization:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred while approving the organization",
    });
  }
});

// ... existing code ...

// Get organization by ID
app.get("/api/v1/organizations/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const organization = await organizationCollections.findOne({
      _id: new ObjectId(id),
    });

    if (!organization) {
      return res.status(404).json({
        success: false,
        message: "Organization not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Organization retrieved successfully",
      data: organization,
    });
  } catch (error) {
    console.error("Error retrieving organization:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred while retrieving the organization",
    });
  }
});

// Get organizations by user ID
app.get("/api/v1/organizations/user/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const organizations = await organizationCollections
      .find({ postBy: new ObjectId(userId) })
      .toArray();

    if (!organizations.length) {
      return res.status(404).json({
        success: false,
        message: "No organizations found for this user",
      });
    }

    res.status(200).json({
      success: true,
      message: "Organizations retrieved successfully",
      data: organizations,
    });
  } catch (error) {
    console.error("Error retrieving organizations by user ID:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred while retrieving organizations by user ID",
    });
  }
});

// ... existing code ...

// Add section to organization
app.post("/organizations/:orgId/sections", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { orgId } = req.params;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const { title, details, image, video } = req.body;

    // Validate required fields
    if (!title || !details) {
      return res.status(400).json({
        success: false,
        message: "Title and details are required",
      });
    }

    const section = {
      title,
      details,
      image,
      video,
      createdAt: new Date(),
    };

    // Update organization with new section
    const result = await organizationCollections.updateOne(
      { _id: new ObjectId(orgId) },
      { $push: { sections: section } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Organization not found or section couldn't be added",
      });
    }

    res.status(200).json({
      success: true,
      message: "Section added successfully",
      data: section,
    });
  } catch (error) {
    console.error("Error adding section:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred while adding the section",
    });
  }
});

// ... existing code ...

// Delete section from organization
app.delete("/organizations/:orgId/sections/:sectionIndex", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { orgId, sectionIndex } = req.params;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Find the organization and update it by removing the section at the specified index
    const result = await organizationCollections.findOneAndUpdate(
      { _id: new ObjectId(orgId) },
      {
        $unset: { [`sections.${sectionIndex}`]: 1 },
      },
      { returnDocument: "after" }
    );

    // Remove null values from the sections array
    await organizationCollections.updateOne(
      { _id: new ObjectId(orgId) },
      {
        $pull: { sections: null },
      }
    );

    if (!result.value) {
      return res.status(404).json({
        success: false,
        message: "Organization not found or section couldn't be deleted",
      });
    }
    res.status(200).json({
      success: true,
      message: "Section deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting section:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred while deleting the section",
    });
  }
});

// ... existing code ...

// Update section in organization
app.put("/organizations/:orgId/sections/:sectionIndex", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { orgId, sectionIndex } = req.params;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const { title, details, image, video } = req.body;

    // Validate required fields
    if (!title || !details) {
      return res.status(400).json({
        success: false,
        message: "Title and details are required",
      });
    }

    // Update the specific section in the organization
    const result = await organizationCollections.findOneAndUpdate(
      { _id: new ObjectId(orgId) },
      {
        $set: {
          [`sections.${sectionIndex}`]: {
            title,
            details,
            image,
            video,
            updatedAt: new Date(),
          },
        },
      },
      { returnDocument: "after" }
    );

    if (!result.value) {
      return res.status(404).json({
        success: false,
        message: "Organization not found or section couldn't be updated",
      });
    }

    res.status(200).json({
      success: true,
      message: "Section updated successfully",
      data: result.value.sections[sectionIndex],
    });
  } catch (error) {
    console.error("Error updating section:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred while updating the section",
    });
  }
});

// ... existing code ...

app.post("/api/v1/activities", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    // Verify token and get user info
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const userId = user._id;
    const { title, date, place, details, image, organizationId } = req.body;

    // Validate required fields
    if (!title || !date || !place || !details || !organizationId) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Create activity document
    const activity = {
      _id: new ObjectId(),
      title,
      date,
      place,
      details,
      image,
      organizationId: new ObjectId(organizationId),
      userName: user.name,
      userId: userId,
      userImage: user.profileImage,
      createdAt: new Date(),
    };

    // First, find the organization
    const organization = await organizationCollections.findOne({
      _id: new ObjectId(organizationId),
    });
    if (!organization) {
      return res.status(404).json({ error: "Organization not found." });
    }

    // Then, update the activities array
    const updatedResult = await organizationCollections.findOneAndUpdate(
      { _id: new ObjectId(organizationId) },
      {
        $set: {
          activities: [...(organization.activities || []), activity],
        },
      },
      { returnDocument: "after" }
    );

    res.status(201).json({
      success: true,
      message: "Activity created successfully",
      activityId: updatedResult.lastErrorObject.updatedExisting
        ? activity._id
        : null,
    });
  } catch (error) {
    console.error("Error creating activity:", error);
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid token" });
    }
    res.status(500).json({ error: "Failed to create activity" });
  }
});

app.put("/api/v1/events/:activityId", async (req, res) => {
  const { activityId } = req.params;
  const { organizationId } = req.body;

  try {
    // Find the event containing the activity
    const organization = await organizationCollections.findOne(
      new ObjectId(organizationId)
    );
    if (!organization) {
      return res
        .status(404)
        .json({ success: false, message: "Activity not found in any event" });
    }
    const activity = organization.activities.find(
      (activity) => activity._id.toString() === activityId
    );
    if (!activity) {
      return res
        .status(404)
        .json({ success: false, message: "Activity not found" });
    }
    if (activity.event) {
      return res
        .status(400)
        .json({ success: false, message: "Activity already on event" });
    }
    activity.event = true;
    await organizationCollections.updateOne(
      { _id: new ObjectId(organizationId) },
      {
        $set: {
          activities: organization.activities,
        },
      }
    );
    res
      .status(200)
      .json({ success: true, message: "Activity moved to event successfully" });
  } catch (error) {
    console.error("Error moving activity:", error);
    res
      .status(500)
      .json({ success: false, message: "Failed to move activity to event." });
  }
});

app.get("/api/v1/activity/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const activity = await organizationCollections.findOne(
      { "activities._id": new ObjectId(id) },
      { projection: { activities: { $elemMatch: { _id: new ObjectId(id) } } } }
    );
    if (!activity) {
      return res.status(404).json({ error: "Activity not found" });
    }
    res.status(200).json({ data: activity.activities[0] });
  } catch (error) {
    console.error("Error getting activity:", error);
    res.status(500).json({ error: "Failed to get activity" });
  }
});

app.get("/organizations/activities", async (req, res) => {
  try {
    const organizations = await organizationCollections
      .find({ status: { $eq: "accepted" } }, { projection: { activities: 1 } })
      .toArray();

    res.status(200).json({
      success: true,
      message: "Organizations retrieved successfully",
      data: organizations,
    });
  } catch (error) {
    console.error("Error retrieving organizations:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred while retrieving organizations",
    });
  }
});

app.delete("/api/v1/activities/:activityId/:orgId", async (req, res) => {
  const { activityId, orgId } = req.params;
  try {
    const org = await organizationCollections.findOne({
      _id: new ObjectId(orgId),
    });
    const activity = org.activities.find(
      (activity) => activity._id.toString() === activityId
    );
    if (!activity) {
      return res.status(404).json({ error: "Activity not found" });
    }
    const updatedOrg = await organizationCollections.findOneAndUpdate(
      { _id: new ObjectId(orgId) },
      { $pull: { activities: { _id: new ObjectId(activityId) } } },
      { returnDocument: "after" }
    );
    res.status(200).json({ success: true, data: updatedOrg });
  } catch (error) {
    console.error("Error getting activity:", error);
    res.status(500).json({ error: "Failed to get activity" });
  }
});

app.put("/api/v1/activities/:activityId/:orgId", async (req, res) => {
  const { activityId, orgId } = req.params;
  const { title, date, place, details, image } = req.body;

  try {
    const updatedOrg = await organizationCollections.findOneAndUpdate(
      { _id: new ObjectId(orgId), "activities._id": new ObjectId(activityId) },
      {
        $set: {
          "activities.$.title": title,
          "activities.$.date": date,
          "activities.$.place": place,
          "activities.$.details": details,
          "activities.$.image": image,
        },
      },
      { returnDocument: "after" }
    );

    if (!updatedOrg) {
      return res
        .status(404)
        .json({ success: false, error: "Activity not found" });
    }

    res.status(200).json({ success: true, data: updatedOrg });
  } catch (error) {
    console.error("Error updating activity:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to update activity" });
  }
});

app.get("/social-organization", async (req, res) => {
  try {
    const organizations = await organizationCollections
      .find({
        status: { $eq: "accepted" },
        orgType: { $eq: "social organization" },
      })
      .toArray();

    res.status(200).json({ success: true, data: organizations });
  } catch (error) {
    console.error("Error retrieving organizations:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred while retrieving organizations",
    });
  }
});

// POST /api/channels
app.post("/api/channels", async (req, res) => {
  try {
    const channelData = req.body;

    // Optionally validate required fields
    if (!channelData.name || !channelData.creator) {
      return res
        .status(400)
        .json({ message: "Name and creator are required." });
    }

    const result = await channelsCollection.insertOne(channelData);
    res.status(201).json({
      message: "Channel created successfully",
      channelId: result.insertedId,
    });
  } catch (error) {
    console.error("Error inserting channel:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// GET /api/channels
app.get("/api/channels", async (req, res) => {
  try {
    const channels = await channelsCollection
      .find({ status: "approved" })
      .toArray();
    res.status(200).json(channels);
  } catch (error) {
    console.error("Error fetching channels:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/channels/admin", async (req, res) => {
  try {
    console.log("hit");
    const channels = await channelsCollection.find({}).toArray();
    res.status(200).json(channels);
  } catch (error) {
    console.error("Error fetching channels:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.patch("/api/channels/:channelId/status", async (req, res) => {
  const { channelId } = req.params;
  const { status } = req.body;

  try {
    const result = await channelsCollection.updateOne(
      { _id: new ObjectId(channelId) },
      { $set: { status } }
    );

    if (result.modifiedCount === 1) {
      res.status(200).json({ message: "Channel status updated successfully." });
    } else {
      res
        .status(404)
        .json({ message: "Channel not found or status unchanged." });
    }
  } catch (error) {
    console.error("Error updating channel status:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/channels/:channelId", async (req, res) => {
  const { channelId } = req.params;

  try {
    const channel = await channelsCollection.findOne({
      _id: new ObjectId(channelId),
    });

    if (!channel) {
      return res.status(404).json({ message: "Channel not found" });
    }

    res.status(200).json(channel);
  } catch (error) {
    console.error("Error fetching channel:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/channels/:channelId/messages", async (req, res) => {
  const { channelId } = req.params;
  const { text, fileUrl, fileType, fileName, senderId, senderName, timestamp } =
    req.body;

  if (!senderId || !channelId) {
    return res.status(400).json({ error: "Missing senderId or channelId." });
  }

  try {
    const newMessage = {
      channelId: new ObjectId(channelId),
      senderId: new ObjectId(senderId),
      senderName,
      text: text || "",
      fileUrl: fileUrl || null,
      fileType: fileType || null,
      fileName: fileName || null,
      timestamp: timestamp ? new Date(timestamp) : new Date(),
    };

    const result = await channelessagesCollection.insertOne(newMessage);

    if (result.insertedId) {
      res
        .status(201)
        .json({ message: { _id: result.insertedId, ...newMessage } });
    } else {
      throw new Error("Message insert failed");
    }
  } catch (err) {
    console.error("Error saving message:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/channels/:channelId/messages", async (req, res) => {
  const { channelId } = req.params;
  console.log(channelId);
  try {
    const messages = await channelessagesCollection
      .find({ channelId: new ObjectId(channelId) })
      .sort({ timestamp: 1 }) // sort by timestamp ascending
      .toArray();

    res.status(200).json({ messages });
  } catch (err) {
    console.error("Error fetching messages:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/api/channels/:channelId/messages/:messageId", async (req, res) => {
  const { channelId, messageId } = req.params;
  const { text } = req.body;

  if (!text || !text.trim()) {
    return res.status(400).json({ error: "Text is required" });
  }

  if (!ObjectId.isValid(channelId) || !ObjectId.isValid(messageId)) {
    return res.status(400).json({ error: "Invalid channelId or messageId" });
  }

  try {
    const result = await channelessagesCollection.updateOne(
      { _id: new ObjectId(messageId), channelId: new ObjectId(channelId) },
      {
        $set: {
          text: text.trim(),
          edited: true,
          editedAt: new Date(),
        },
      }
    );

    if (result.modifiedCount === 1) {
      const updatedMessage = await channelessagesCollection.findOne({
        _id: new ObjectId(messageId),
      });
      res.status(200).json(updatedMessage);
    } else {
      res.status(404).json({ error: "Message not found or unchanged" });
    }
  } catch (err) {
    console.error("Error updating message:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/channels/:channelId/messages/:messageId", async (req, res) => {
  const { channelId, messageId } = req.params;

  if (!ObjectId.isValid(channelId) || !ObjectId.isValid(messageId)) {
    return res.status(400).json({ error: "Invalid channelId or messageId" });
  }

  try {
    const message = await channelessagesCollection.findOne({
      _id: new ObjectId(messageId),
      channelId: new ObjectId(channelId),
    });

    if (!message) {
      return res.status(404).json({ error: "Message not found" });
    }

    res.status(200).json({ message });
  } catch (err) {
    console.error("Error fetching message:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete("/api/channels/:channelId/messages/:messageId", async (req, res) => {
  const { channelId, messageId } = req.params;

  if (!ObjectId.isValid(channelId) || !ObjectId.isValid(messageId)) {
    return res.status(400).json({ error: "Invalid channelId or messageId" });
  }

  try {
    const result = await channelessagesCollection.deleteOne({
      _id: new ObjectId(messageId),
      channelId: new ObjectId(channelId),
    });

    if (result.deletedCount === 1) {
      res.status(200).json({ message: "Message deleted successfully" });
    } else {
      res.status(404).json({ error: "Message not found" });
    }
  } catch (err) {
    console.error("Error deleting message:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/books/nearby", async (req, res) => {
  const { longitude, latitude, maxDistance = 4000 } = req.query;

  if (!longitude || !latitude) {
    return res.status(400).send({
      success: false,
      message: "Longitude and latitude are required.",
    });
  }

  try {
    const nearbyBooks = await bookCollections
      .aggregate([
        {
          $geoNear: {
            near: {
              type: "Point",
              coordinates: [parseFloat(longitude), parseFloat(latitude)],
            },
            distanceField: "distance",
            maxDistance: parseFloat(maxDistance), // in meters
            spherical: true,
          },
        },
      ])
      .toArray();

    res.send({
      success: true,
      data: nearbyBooks,
    });

    console.log("Nearby books found:", nearbyBooks);
  } catch (error) {
    console.error("Error fetching nearby books:", error);
    res.status(500).send({
      success: false,
      message: "An unexpected error occurred.",
    });
  }
});

app.post("/api/courses", async (req, res) => {
  const courseData = req.body;
  // Save courseData to MongoDB
  const savedCourse = await coursesCollection.insertOne(courseData);
  res.status(201).json(savedCourse);
});

app.get("/api/courses", async (req, res) => {
  try {
    const courses = await coursesCollection.find().toArray();
    res.status(200).json(courses);
  } catch (error) {
    console.error("Failed to fetch courses:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/api/courses/:id/videos", async (req, res) => {
  const courseId = req.params.id;
  const videoData = req.body;

  try {
    const course = await coursesCollection.findOne({
      _id: new ObjectId(courseId),
    });

    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }

    // Add the video to the course's `videos` array (create array if it doesn't exist)
    const updatedCourse = await coursesCollection.findOneAndUpdate(
      { _id: new ObjectId(courseId) },
      {
        $push: {
          videos: {
            ...videoData,
          },
        },
      },
      { returnDocument: "after" } // return the updated course
    );

    res.status(200).json(updatedCourse.value);
  } catch (error) {
    console.error("Error adding video to course:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.delete("/api/courses/:id/videos/:videoIndex", async (req, res) => {
  const courseId = req.params.id;
  const videoIndex = parseInt(req.params.videoIndex);

  try {
    const course = await coursesCollection.findOne({
      _id: new ObjectId(courseId),
    });

    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }

    if (
      !Array.isArray(course.videos) ||
      videoIndex < 0 ||
      videoIndex >= course.videos.length
    ) {
      return res.status(400).json({ message: "Invalid video index" });
    }

    // Remove the video at the specified index
    course.videos.splice(videoIndex, 1);

    // Update the course with the modified videos array
    const updatedCourse = await coursesCollection.findOneAndUpdate(
      { _id: new ObjectId(courseId) },
      { $set: { videos: course.videos } },
      { returnDocument: "after" }
    );

    res.status(200).json(updatedCourse.value);
  } catch (error) {
    console.error("Error removing video from course:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.delete("/api/courses/:id", async (req, res) => {
  const courseId = req.params.id;

  try {
    const result = await coursesCollection.deleteOne({
      _id: new ObjectId(courseId),
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Course not found" });
    }

    res.status(200).json({ message: "Course removed successfully" });
  } catch (error) {
    console.error("Error deleting course:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/courses/:id", async (req, res) => {
  const courseId = req.params.id;

  try {
    const course = await coursesCollection.findOne({
      _id: new ObjectId(courseId),
    });

    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }

    res.status(200).json(course);
  } catch (error) {
    console.error("Error fetching course:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/market-seller-request", async (req, res) => {
  const { sellerData } = req.body;
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

    const userId = user._id;

    // sellerData + extra fields
    const newSeller = {
      ...sellerData,
      userId, // কে রিকোয়েস্ট করলো সেটা ট্র্যাক করার জন্য
      status: "pending",
      createdAt: new Date(),
    };

    const result = await sellerCollections.insertOne(newSeller);

    res.status(201).json({
      message: "Seller request submitted successfully.",
      sellerId: result.insertedId,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/get-market-product", async (req, res) => {
  try {
    const products = await productsCollection.find().toArray();
    res.status(200).json({
      success: true,
      products,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/get-product/:productId", async (req, res) => {
  const { productId } = req.params; // ✅ get from params
  try {
    const product = await productsCollection.findOne({
      _id: new ObjectId(productId),
    }); // ✅ query correctly
    if (!product) {
      return res
        .status(404)
        .json({ success: false, message: "Product not found" });
    }
    res.status(200).json({
      success: true,
      product,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/get-product-categories", async (req, res) => {
  try {
    const categories = await productsCategories.find().toArray();
    res.status(200).json({
      success: true,
      categories: categories,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/get-category/:categoryId", async (req, res) => {
  const { categoryId } = req.params;
  try {
    const category = await productsCategories.findOne({
      _id: new ObjectId(categoryId),
    });
    res.status(200).json({
      success: true,
      category: category,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/get-product-category", async (req, res) => {
  const { category } = req.query; // ✅ GET request-এ query ব্যবহার করুন

  try {
    const products = await productsCollection.find({ category }).toArray();
    res.status(200).json({
      success: true,
      products,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/search-products", async (req, res) => {
  try {
    const { q } = req.query; // search keyword

    if (!q || q.trim() === "") {
      return res
        .status(400)
        .json({ success: false, message: "Search query required" });
    }

    // MongoDB regex search
    const products = await productsCollection
      .find({
        $or: [
          { title: { $regex: q, $options: "i" } }, // title match
          { description: { $regex: q, $options: "i" } }, // description match
          { category: { $regex: q, $options: "i" } }, // category match
        ],
      })
      .limit(50) // optional: max 50 results
      .toArray();

    res.status(200).json({
      success: true,
      products,
    });
  } catch (error) {
    console.error("Search error:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// fetch user's cart
app.get("/cart/:userId", async (req, res) => {
  const { userId } = req.params;

  if (!userId) {
    return res
      .status(400)
      .json({ success: false, message: "User ID is required" });
  }

  try {
    const cart = await cartsCollection.findOne({ userId });

    if (!cart) {
      return res.status(200).json({ success: true, items: [] }); // empty cart
    }

    res.status(200).json({ success: true, items: cart.items });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Add or update product in cart
app.post("/cart/add", async (req, res) => {
  const { userId, product, quantity } = req.body;
  if (!userId || !product || !quantity) {
    return res.status(400).json({ success: false, message: "Missing data" });
  }

  try {
    // Check if user already has a cart
    const cart = await cartsCollection.findOne({ userId });

    if (cart) {
      // Check if product already exists in cart
      const existingItem = cart.items.find(
        (item) => item.productId === product._id
      );

      if (existingItem) {
        // Update quantity
        await cartsCollection.updateOne(
          { userId, "items.productId": product._id },
          { $inc: { "items.$.quantity": quantity } }
        );
      } else {
        // Add new product
        await cartsCollection.updateOne(
          { userId },
          { $push: { items: { ...product, productId: product._id, quantity } } }
        );
      }
    } else {
      // Create a new cart for the user
      await cartsCollection.insertOne({
        userId,
        items: [{ ...product, productId: product._id, quantity }],
      });
    }

    res.status(200).json({ success: true, message: "Product added to cart" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// PATCH /cart/update
app.patch("/cart/update", async (req, res) => {
  const { userId, productId, quantity } = req.body;

  if (!userId || !productId || quantity === undefined) {
    return res
      .status(400)
      .json({ success: false, message: "Missing required fields" });
  }

  try {
    const cart = await cartsCollection.findOne({ userId });

    if (!cart) {
      return res
        .status(404)
        .json({ success: false, message: "Cart not found" });
    }

    // Update quantity of the product
    const updatedItems = cart.items.map((item) =>
      item?._id.toString() === productId
        ? { ...item, quantity: Number(quantity) }
        : item
    );

    await cartsCollection.updateOne(
      { userId },
      { $set: { items: updatedItems } }
    );

    res.status(200).json({
      success: true,
      message: "Quantity updated",
      items: updatedItems,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// DELETE /cart/remove/:productId?userId=...
app.delete("/cart/remove/:productId", async (req, res) => {
  const { productId } = req.params;
  const { userId } = req.query;
  if (!userId || !productId) {
    return res
      .status(400)
      .json({ success: false, message: "Missing required fields" });
  }

  try {
    const cart = await cartsCollection.findOne({ userId });

    if (!cart) {
      return res
        .status(404)
        .json({ success: false, message: "Cart not found" });
    }

    // Remove the product
    const updatedItems = cart.items.filter(
      (item) => item?._id?.toString() !== productId
    );

    await cartsCollection.updateOne(
      { userId },
      { $set: { items: updatedItems } }
    );

    res
      .status(200)
      .json({ success: true, message: "Item removed", items: updatedItems });
  } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.post("/orders/create", async (req, res) => {
  try {
    const {
      userId,
      items,
      shippingInfo,
      totalAmount,
      subtotal,
      deliveryCharges,
      totalProducts,
      deliveryChargePerProduct,
      paymentStatus,
      orderSource,
    } = req.body;

    if (!items || items.length === 0) {
      return res
        .status(400)
        .json({ success: false, message: "No items in order" });
    }

    const newOrder = {
      userId,
      items,
      shippingInfo,
      totalAmount,
      subtotal,
      deliveryCharges,
      totalProducts,
      deliveryChargePerProduct,
      paymentStatus,
      orderStatus: "pending",
      orderSource,
      createdAt: new Date(),
    };

    // 1️⃣ Order create
    const result = await ordersCollection.insertOne(newOrder);

    // 2️⃣ Cart before clear
    const cartBefore = await cartsCollection.findOne({ userId });

    const cartBeforeObjId = await cartsCollection.findOne({
      userId: new ObjectId(userId),
    });

    // 3️⃣ Try clear cart (handle both string & ObjectId cases)
    const clearResult = await cartsCollection.updateOne(
      {
        $or: [
          { userId: userId }, // যদি string হিসেবে save থাকে
          { userId: new ObjectId(userId) }, // যদি ObjectId হিসেবে save থাকে
        ],
      },
      { $set: { items: [] } }
    );

    // 4️⃣ Cart after clear
    const cartAfter = await cartsCollection.findOne({ userId });

    res.status(201).json({
      success: true,
      message: "Order created successfully",
      orderId: result.insertedId,
    });
  } catch (error) {
    console.error("❌ Error in /orders/create:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.patch("/payments/:orderId/confirm", async (req, res) => {
  try {
    const { orderId } = req.params;

    const result = await ordersCollection.updateOne(
      { _id: new ObjectId(orderId) },
      { $set: { paymentStatus: "confirmed", confirmedAt: new Date() } }
    );

    if (result.modifiedCount > 0) {
      res.json({ success: true, message: "Order confirmed successfully" });
    } else {
      res.status(404).json({ success: false, message: "Order not found" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// সব pending order আনবে ইউজারের জন্য
app.get("/payments/pending/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const orders = await ordersCollection
      .find({
        userId,
        paymentStatus: "pending",
      })
      .toArray();

    res.json({ success: true, orders });
  } catch (error) {
    console.error("❌ Error fetching pending orders:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.get("/payments/confirmed/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const orders = await ordersCollection
      .find({
        userId,
        paymentStatus: "confirmed",
      })
      .toArray();

    res.json({ success: true, orders });
  } catch (error) {
    console.error("❌ Error fetching pending orders:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Order confirm করার endpoint
app.patch("/payments/confirm/:orderId", async (req, res) => {
  try {
    const { orderId } = req.params;
    const result = await ordersCollection.updateOne(
      { _id: new ObjectId(orderId) },
      { $set: { paymentStatus: "confirmed" } }
    );

    res.json({ success: true, message: "Order confirmed", result });
  } catch (error) {
    console.error("❌ Error confirming order:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.post("/addresses", async (req, res) => {
  try {
    const { addressData } = req.body;

    if (
      !addressData ||
      !addressData.type ||
      !addressData.fullAddress ||
      !addressData.phone
    ) {
      return res
        .status(400)
        .json({ success: false, message: "All fields are required" });
    }

    // যদি isDefault true হয়, তাহলে আগের default address false করে দাও
    if (addressData.isDefault) {
      await addressesCollection.updateMany(
        { userId: addressData.userId, isDefault: true },
        { $set: { isDefault: false } }
      );
    }

    const newAddress = {
      ...addressData,
      isDefault: !!addressData.isDefault,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await addressesCollection.insertOne(newAddress);

    res.status(201).json({
      success: true,
      message: "Address added successfully",
      address: { ...newAddress, _id: result.insertedId },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.put("/addresses/:id", async (req, res) => {
  try {
    const addressId = req.params.id;
    const { addressData } = req.body;

    if (
      !addressData ||
      !addressData.type ||
      !addressData.fullAddress ||
      !addressData.phone
    ) {
      return res
        .status(400)
        .json({ success: false, message: "All fields are required" });
    }

    // যদি isDefault true হয়, তাহলে আগের default address false করে দাও
    if (addressData.isDefault) {
      await addressesCollection.updateMany(
        { userId: addressData.userId, isDefault: true },
        { $set: { isDefault: false } }
      );
    }

    const updated = await addressesCollection.findOneAndUpdate(
      { _id: new ObjectId(addressId) },
      {
        $set: {
          type: addressData.type,
          fullAddress: addressData.fullAddress,
          phone: addressData.phone,
          isDefault: !!addressData.isDefault,
          updatedAt: new Date(),
        },
      },
      { returnDocument: "after" }
    );

    if (!updated.value) {
      return res
        .status(404)
        .json({ success: false, message: "Address not found" });
    }

    res.status(200).json({
      success: true,
      message: "Address updated successfully",
      address: updated.value,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.get("/addresses/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!userId) {
      return res
        .status(400)
        .json({ success: false, message: "User ID is required" });
    }

    const addresses = await addressesCollection
      .find({ userId: userId })
      .sort({ isDefault: -1, createdAt: -1 }) // Default address আগে দেখাবে
      .toArray();

    res.status(200).json({
      success: true,
      addresses,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.delete("/addresses/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res
        .status(400)
        .json({ success: false, message: "Address ID is required" });
    }

    const result = await addressesCollection.deleteOne({
      _id: new ObjectId(id),
    });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Address not found" });
    }

    res
      .status(200)
      .json({ success: true, message: "Address deleted successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.get("/seller-requests", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user || user.role !== "admin") {
      return res.status(403).json({ error: "Access denied" });
    }

    const requests = await sellerCollections.find().sort({createdAt: -1}).toArray();
    res.status(200).json({ success: true, requests });
  } catch (error) {
    console.error("Error fetching seller requests:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Approve or Reject Seller Request
app.patch("/seller-requests/:id", async (req, res) => {
  const { id } = req.params;
  const { status } = req.body; // "approved" | "rejected"
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user || user.role !== "admin") {
      return res.status(403).json({ error: "Access denied" });
    }

    const result = await sellerCollections.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status } }
    );

    res.status(200).json({
      message: `Seller request ${status} successfully.`,
      result,
    });
  } catch (error) {
    console.error("Error updating seller request:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// get all approved sellers
app.get("/sellers", async (req, res) => {
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

    if (user.role !== "admin") {
      return res.status(403).json({ error: "Access denied. Admin only." });
    }

    const sellers = await sellerCollections
      .find({ status: "approved" }) // শুধু approved seller দেখাবে
      .toArray();

    res.status(200).json({ success: true, sellers });
  } catch (error) {
    console.error("Error fetching sellers:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// suspend seller
app.patch("/sellers/:id/suspend", async (req, res) => {
  const { id } = req.params;
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

    if (user.role !== "admin") {
      return res.status(403).json({ error: "Access denied. Admin only." });
    }

    const result = await sellerCollections.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status: "suspended" } }
    );

    if (result.modifiedCount === 0) {
      return res
        .status(404)
        .json({ error: "Seller not found or already suspended." });
    }

    res
      .status(200)
      .json({ success: true, message: "Seller suspended successfully." });
  } catch (error) {
    console.error("Error suspending seller:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/sellers/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const seller = await sellerCollections.findOne({ _id: new ObjectId(id) });
    if (!seller) {
      return res.status(404).json({ error: "Seller not found." });
    }
    res.status(200).json({ success: true, seller });
  } catch (error) {
    console.error("Error fetching seller:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// GET /sellers/check/:userId
app.get("/sellers/check/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    // ObjectId conversion
    const seller = await sellerCollections.findOne({
      userId: new ObjectId(userId),
      status: "approved", // শুধুমাত্র approved seller খুঁজবে
    });

    if (!seller) {
      return res.json({ isSeller: false });
    }

    // seller found
    res.json({ isSeller: true, seller });
  } catch (error) {
    console.error("Error checking seller:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// GET /seller-request/:userId
app.get("/seller-request/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const request = await sellerCollections.findOne({
      userId: new ObjectId(userId),
    });
    if (request) {
      res.status(200).json({ success: true, request });
    } else {
      res.status(200).json({ success: true, request: null }); // no request found
    }
  } catch (error) {
    console.error("Error fetching seller request:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.post("/add-seller-product", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  try {
    const product = req.body;
    const result = await productsCollection.insertOne(product);
    res.status(201).json({ success: true, productId: result.insertedId });
  } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.get("/get-seller-products", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find user from token
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Fetch all products for that vendor
    const products = await productsCollection
      .find({ vendorId: user._id.toString() })
      .toArray();

    res.status(200).json({ success: true, products });
  } catch (error) {
    console.error("Error fetching seller products:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.delete("/delete-product/:id", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find user from token
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const { id } = req.params;

    // Delete only if the product belongs to this vendor
    const result = await productsCollection.deleteOne({
      _id: new ObjectId(id),
      vendorId: user._id.toString(), // if stored as string
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Product not found or not authorized",
      });
    }

    res
      .status(200)
      .json({ success: true, message: "Product deleted successfully" });
  } catch (error) {
    console.error("Error deleting product:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// ✅ Update a product by ID
app.put("/update-product/:id", async (req, res) => {
  const { id } = req.params;
  const updatedData = req.body;

  try {
    const result = await productsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.status(200).json({
      success: true,
      message: "Product updated successfully",
    });
  } catch (error) {
    console.error("Error updating product:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
// Get all orders for a specific seller
app.get("/seller/orders/:vendorId", async (req, res) => {
  const { vendorId } = req.params;

  try {
    const orders = await ordersCollection
      .find({
        items: { $elemMatch: { vendorId: vendorId } }, // ✅ Ensure seller's items exist
      })
      .toArray();

    console.log("Found orders:", orders.length);
    res.status(200).json({ success: true, orders });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Update status of a specific item in an order
app.put("/seller/orders/:orderId/item/:itemId", async (req, res) => {
  const { orderId, itemId } = req.params;
  const { status } = req.body;

  try {
    // প্রথমে আইটেম স্ট্যাটাস আপডেট করা
    const result = await ordersCollection.updateOne(
      { _id: new ObjectId(orderId), "items._id": itemId },
      { $set: { "items.$.itemOrderStatus": status } }
    );

    if (result.matchedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Order or item not found" });
    }

    // আপডেটেড অর্ডার বের করা
    const order = await ordersCollection.findOne({
      _id: new ObjectId(orderId),
    });

    if (!order) {
      return res
        .status(404)
        .json({ success: false, message: "Order not found" });
    }

    // আইটেম স্ট্যাটাস অনুযায়ী অর্ডারের স্ট্যাটাস নির্ধারণ
    const itemStatuses = order.items.map((item) => item.itemOrderStatus);

    let newOrderStatus;
    if (itemStatuses.every((s) => s === "pending")) {
      newOrderStatus = "pending";
    } else if (itemStatuses.every((s) => s === "processing")) {
      newOrderStatus = "processing";
    } else if (itemStatuses.every((s) => s === "ready-to-ship")) {
      newOrderStatus = "ready-to-ship";
    } else if (itemStatuses.every((s) => s === "shipped")) {
      newOrderStatus = "shipped";
    } else if (itemStatuses.every((s) => s === "delivered")) {
      newOrderStatus = "delivered";
    } else if (itemStatuses.every((s) => s === "cancelled")) {
      newOrderStatus = "cancelled";
    } else {
      // মিক্সড স্ট্যাটাসের ক্ষেত্রে সাধারণত processing
      newOrderStatus = "processing";
    }

    // অর্ডারের মূল স্ট্যাটাস আপডেট করা
    await ordersCollection.updateOne(
      { _id: new ObjectId(orderId) },
      { $set: { orderStatus: newOrderStatus } }
    );

    res.status(200).json({
      success: true,
      message: "Item and order status updated successfully",
      itemStatus: status,
      orderStatus: newOrderStatus,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.get("/seller-payments", async (req, res) => {
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

    // seller এর order খুঁজে বের করা
    const orders = await ordersCollection
      .find({
        "items.vendorId": user._id.toString(), // vendorId যদি string আকারে থাকে
      })
      .toArray();

    const sellerItems = [];

    orders.forEach((order) => {
      order.items.forEach((item) => {
        if (item.vendorId.toString() === user._id.toString()) {
          sellerItems.push({
            ...item, // first copy item properties
            orderId: order._id,
            paymentStatus: order.paymentStatus,
            orderStatus: order.orderStatus,
            shippingInfo: order.shippingInfo,
            createdAt: order.createdAt, // override item.createdAt
          });
        }
      });
    });

    res.status(200).json({ success: true, items: sellerItems });
  } catch (error) {
    console.error("❌ Error in /seller-payments:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Withdraw request create
app.post("/seller-withdraw", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await usersCollections.findOne({ number: decoded.number });

    const { amount, method, methodDetails } = req.body;
    const seller = await sellerCollections.findOne({
      userId: new ObjectId(user._id),
    });
    if (!seller) return res.status(404).json({ message: "Seller not found" });

    // Orders fetch
    const orders = await ordersCollection
      .find({
        "items.vendorId": seller.userId.toString(), // vendorId string হলে কাজ করবে
        "items.itemOrderStatus": "delivered",
        paymentStatus: "confirmed",
      })
      .toArray();
    // Seller earnings calculate
    const earnings = orders
      .flatMap((o) => o.items)
      .filter((i) => {
        const match =
          i.vendorId.toString() === seller.userId.toString() &&
          i.itemOrderStatus === "delivered";
        return match;
      })
      .reduce((acc, i) => {
        const price = Number(i.price);
        const qty = Number(i.quantity);
        console.log(`➕ Adding: ${price} x ${qty} = ${price * qty}`);
        return acc + price * qty;
      }, 0);

    // Previous withdraw history
    const history = await withdrawsCollection
      .find({ sellerId: seller._id })
      .toArray();
    const totalWithdrawn = history.reduce((a, h) => a + h.amount, 0);
    const withdrawable = earnings - totalWithdrawn;

    if (amount > withdrawable) {
      console.log("❌ Insufficient Balance:", {
        requested: amount,
        withdrawable,
      });
      return res
        .status(400)
        .json({ message: "Insufficient withdrawable balance" });
    }

    const withdrawRequest = {
      sellerId: seller._id,
      amount,
      method,
      methodDetails,
      status: "pending", // admin approve করবে
      createdAt: new Date(),
    };

    await withdrawsCollection.insertOne(withdrawRequest);
    res
      .status(200)
      .json({ success: true, message: "Withdraw request submitted" });
  } catch (err) {
    console.error("🔥 Error:", err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Withdraw history get
app.get("/seller-withdraw-history", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    const seller = await sellerCollections.findOne({
      userId: new ObjectId(user._id),
    });
    if (!seller) return res.status(404).json({ message: "Seller not found" });

    const history = await withdrawsCollection
      .find({ sellerId: seller._id })
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ success: true, history });
  } catch (err) {
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/get-admin-products", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find user from token
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user || user.role !== "admin") {
      return res.status(404).json({ error: "User not found." });
    }

    // Fetch all products for that vendor
    const products = await productsCollection.find().sort({createdAt: -1}).toArray();

    res.status(200).json({ success: true, products });
  } catch (error) {
    console.error("Error fetching seller products:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.delete("/delete-admin-product/:id", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find user from token
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user || user.role !== "admin") {
      return res.status(404).json({ error: "User not found." });
    }

    const { id } = req.params;

    // Delete only if the product belongs to this vendor
    const result = await productsCollection.deleteOne({
      _id: new ObjectId(id),
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Product not found or not authorized",
      });
    }

    res
      .status(200)
      .json({ success: true, message: "Product deleted successfully" });
  } catch (error) {
    console.error("Error deleting product:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.put("/update-admin-product/:id", async (req, res) => {
  const { id } = req.params;
  const updatedData = req.body;

  try {
    const result = await productsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.status(200).json({
      success: true,
      message: "Product updated successfully",
    });
  } catch (error) {
    console.error("Error updating product:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/add-admin-category", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  try {
    const { name } = req.body;
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find user from token
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user || user.role !== "admin") {
      return res.status(404).json({ error: "User not found." });
    }
    if (!name) {
      return res
        .status(400)
        .json({ success: false, message: "Category name required" });
    }

    const exists = await productsCategories.findOne({ name: name.trim() });
    if (exists) {
      return res
        .status(400)
        .json({ success: false, message: "Category already exists" });
    }

    const result = await productsCategories.insertOne({
      name: name.trim(),
      createdAt: new Date(),
    });

    res.status(201).json({
      success: true,
      message: "Category added",
      categoryId: result.insertedId,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ✅ 3. Update category
app.put("/update-admin-category/:id", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  try {
    const { id } = req.params;
    const { name } = req.body;

    const decoded = jwt.verify(token, JWT_SECRET);

    // Find user from token
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user || user.role !== "admin") {
      return res.status(404).json({ error: "User not found." });
    }

    if (!ObjectId.isValid(id)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid category id" });
    }

    const result = await productsCategories.updateOne(
      { _id: new ObjectId(id) },
      { $set: { name: name.trim() } }
    );

    if (result.matchedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Category not found" });
    }

    res.status(200).json({ success: true, message: "Category updated" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ✅ 4. Delete category
app.delete("/delete-admin-category/:id", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  try {
    const { id } = req.params;
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find user from token
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user || user.role !== "admin") {
      return res.status(404).json({ error: "User not found." });
    }
    if (!ObjectId.isValid(id)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid category id" });
    }

    const result = await productsCategories.deleteOne({
      _id: new ObjectId(id),
    });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Category not found" });
    }

    res.status(200).json({ success: true, message: "Category deleted" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/admin-products/orders", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find user from token
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user || user.role !== "admin") {
      return res.status(404).json({ error: "User not found." });
    }
    const orders = await ordersCollection.find().sort({createdAt: -1}).toArray();
    res.status(200).json({ success: true, orders });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.patch("/admin-products/orders/:orderId/status", async (req, res) => {
  const { orderId } = req.params;
  const { status } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find user from token
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user || user.role !== "admin") {
      return res.status(404).json({ error: "User not found." });
    }
    const result = await ordersCollection.updateOne(
      { _id: new ObjectId(orderId) },
      { $set: { orderStatus: status, updatedAt: new Date() } }
    );

    res
      .status(200)
      .json({ success: true, message: "Order status updated", result });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

// Update payment status
app.patch("/admin-products/orders/:orderId/payment", async (req, res) => {
  const { orderId } = req.params;
  const { status } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find user from token
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user || user.role !== "admin") {
      return res.status(404).json({ error: "User not found." });
    }
    const result = await ordersCollection.updateOne(
      { _id: new ObjectId(orderId) },
      { $set: { paymentStatus: status, updatedAt: new Date() } }
    );

    res
      .status(200)
      .json({ success: true, message: "Payment status updated", result });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

app.get("/admin-withdrawData", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user || user.role !== "admin") {
      return res.status(404).json({ error: "User not found." });
    }
    const withdrawData = await withdrawsCollection
      .find()
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ success: true, withdrawData });
  } catch (err) {
    res.status(500).json({ message: "Internal server error" });
  }
});

app.patch("/admin-withdraw/:withdrawId/status", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user || user.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admins only" });
    }

    const { withdrawId } = req.params;
    const { status } = req.body; // pending, approved, rejected

    const result = await withdrawsCollection.updateOne(
      { _id: new ObjectId(withdrawId) },
      { $set: { status } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: "Withdraw request not found" });
    }

    res.status(200).json({ message: "Withdraw status updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/seller/banner-requests/:sellerId", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res.status(403).json({ message: "Forbidden: Seller only" });
    }

    const banners = await bannersCollection
      .find({ sellerId: req.params.sellerId })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({ success: true, banners });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/seller/banner-request", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  const { title, description, ctaText, ctaLink, image, sellerId, sellerName } =
    req.body;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res.status(403).json({ message: "Forbidden: Seller only" });
    }

    const newBanner = {
      title,
      description,
      ctaText,
      ctaLink,
      image,
      sellerId,
      sellerName,
      status: "pending",
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await bannersCollection.insertOne(newBanner);
    res.json({ success: true, banner: result.insertedId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.patch("/seller/banner-request/:bannerId", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  const { bannerId } = req.params;
  const { title, description, ctaText, ctaLink, image } = req.body;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res.status(403).json({ message: "Forbidden: Seller only" });
    }
    const banner = await bannersCollection.findOne({
      _id: new ObjectId(bannerId),
    });

    if (!banner) return res.status(404).json({ message: "Banner not found" });
    if (banner.status === "approved")
      return res
        .status(400)
        .json({ message: "Approved banner cannot be edited" });

    await bannersCollection.updateOne(
      { _id: new ObjectId(bannerId) },
      {
        $set: {
          title,
          description,
          ctaText,
          ctaLink,
          image,
          updatedAt: new Date(),
        },
      }
    );

    res.json({ success: true, message: "Banner updated" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.delete("/seller/banner-request/:bannerId", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  const { bannerId } = req.params;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res.status(403).json({ message: "Forbidden: Seller only" });
    }
    const banner = await bannersCollection.findOne({
      _id: new ObjectId(bannerId),
    });
    if (!banner) return res.status(404).json({ message: "Banner not found" });
    if (banner.status === "approved")
      return res
        .status(400)
        .json({ message: "Approved banner cannot be deleted" });

    await bannersCollection.deleteOne({ _id: new ObjectId(bannerId) });
    res.json({ success: true, message: "Banner deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/admin/banner-requests", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user || user.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admins only" });
    }
    const banners = await bannersCollection
      .find()
      .sort({ createdAt: -1 })
      .toArray();

    res.json({ success: true, banners });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// PATCH /admin/banner-request/:id/status
app.patch("/admin/banner-request/:id/status", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  const { id } = req.params;
  const { status } = req.body; // expected: "pending", "approved", "rejected"

  if (!["pending", "approved", "rejected"].includes(status)) {
    return res.status(400).json({ message: "Invalid status value" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user || user.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admins only" });
    }

    const banner = await bannersCollection.findOne({ _id: new ObjectId(id) });
    if (!banner) return res.status(404).json({ message: "Banner not found" });

    // Remove restriction, always allow status change
    await bannersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status: status } }
    );

    res.json({ success: true, message: `Banner status updated to ${status}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});



app.get("/user-all/orders/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const orders = await ordersCollection
      .find({
        userId,
      })
      .toArray();

    res.json({ success: true, orders });
  } catch (error) {
    console.error("❌ Error fetching orders:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.get("/home-banners", async (req, res) => {
  try {
    const banners = await bannersCollection
      .find()
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ success: true, banners });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// নতুন আসা product → createdAt দিয়ে sort
app.get("/products/latest", async (req, res) => {
  try {
    const latestProducts = await productsCollection
      .find()
      .sort({ createdAt: -1 }) // নতুন আগে
      .limit(10)
      .toArray();

    res.status(200).json({ success: true, products: latestProducts });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/products/most-popular-category", async (req, res) => {
  try {
    const result = await productsCollection
      .aggregate([
        {
          $group: {
            _id: "$category",        // category অনুযায়ী group
            count: { $sum: 1 }       // প্রতিটা category এর product সংখ্যা
          }
        },
        { $sort: { count: -1 } },    // বেশি product আগে
        { $limit: 1 }                // শুধু ১টা category আনবে
      ])
      .toArray();

    if (!result.length) {
      return res.status(404).json({ message: "No categories found" });
    }

    const mostPopularCategory = result[0]._id;

    // এবার সেই category এর product গুলো আনবো
    const products = await productsCollection
      .find({ category: mostPopularCategory })
      .limit(20)
      .toArray();

    res.status(200).json({
      success: true,
      category: mostPopularCategory,
      products,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});


// Rating >= 4.5 হলে টপ rated products
app.get("/products/top-rated", async (req, res) => {
  try {
    const topRatedProducts = await productsCollection
      .find({ rating: { $gte: 4.5 } })
      .sort({ rating: -1 })
      .limit(10)
      .toArray();

    res.status(200).json({ success: true, products: topRatedProducts });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/products/featured", async (req, res) => {
  try {
    const products = await productsCollection.find({ isFeatured: true }).toArray();
    res.json({ success: true, products });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Highest discount products
app.get("/products/high-discounts", async (req, res) => {
  try {
    const products = await productsCollection
      .aggregate([
        {
          $addFields: {
            discountPercent: {
              $round: [
                {
                  $multiply: [
                    { $divide: [{ $subtract: ["$price", "$discountPrice"] }, "$price"] },
                    100
                  ]
                },
                0
              ]
            }
          }
        },
        { $sort: { discountPercent: -1 } },
        { $limit: 5 }
      ])
      .toArray();

    res.json({ success: true, products });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});


const server = app.listen(port, () => {
  console.log(`Server running http://localhost:${port}`);
});

const io = new Server(server, {
  cors: {
    origin: ["https://flybook.com.bd", "https://flybook-f23c5.web.app"], // আপনার ফ্রন্টএন্ডের পোর্ট
    methods: ["GET", "POST"],
    credentials: true,
  },
});

io.on("connection", (socket) => {
  // ইউজারকে রুমে যোগ করা
  socket.on("joinRoom", (userId) => {
    const roomId = [userId].sort().join("-");
    socket.join(roomId);
    console.log("user join", roomId);
    socket.emit("connected");
  });

  socket.on("joinUser", (userId) => {
    const roomId = userId;
    socket.join(roomId); // ইউজারকে রুমে যোগ করা
    console.log("user joined", roomId);
    socket.emit("connected");
  });

  socket.on("sendRequest", async (notificationData) => {
    const {
      senderId,
      senderName,
      receoientId,
      notifyText,
      senderProfile,
      roomId,
      type,
    } = notificationData;
    try {
      const newNotifyReq = {
        senderId: ObjectId(senderId),
        receoientId: ObjectId(receoientId),
        senderProfile,
        senderName,
        notifyText,
        type,
        timestamp: new Date(),
      };
      await notifyCollections.insertOne(newNotifyReq);
      socket.to(roomId).emit("receiveNotify", {
        senderId,
        senderName,
        senderProfile,
        notifyText,
        type,
        timestamp: new Date(),
      });
    } catch (error) {
      console.log(error);
    }
  });
  // মেসেজ পাঠানো
  socket.on("sendMessage", async (messageData) => {
    const {
      senderId,
      senderName,
      receoientId,
      messageText,
      roomId,
      messageType,
      mediaUrl,
    } = messageData;
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
    console.log("A user disconnected:", socket.id);
  });
});

// Start the serve
