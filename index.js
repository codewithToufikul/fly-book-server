const express = require("express");
const cors = require("cors");
const compression = require("compression");
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
const PDFDocument = require("pdfkit");
const stream = require("stream");
const dns = require("dns");

// Prefer IPv4 first to avoid DNS resolution issues in some environments
try {
  if (typeof dns.setDefaultResultOrder === 'function') {
    dns.setDefaultResultOrder('ipv4first');
  }
} catch (_) {}

const app = express();
const port = process.env.PORT || 5000;

// Performance: Compression middleware (gzip/brotli)
app.use(compression({
  level: 6, // Compression level (1-9, 6 is good balance)
  filter: (req, res) => {
    // Don't compress if client doesn't support it
    if (req.headers['x-no-compression']) {
      return false;
    }
    // Use compression for all other requests
    return compression.filter(req, res);
  }
}));

// Middleware
app.use(
  cors({
    origin: ["https://flybook.com.bd", "https://flybook-f23c5.web.app", "http://localhost:5173"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// Performance: Cache headers for static-like responses
app.use((req, res, next) => {
  // Cache GET requests for 5 minutes (except auth endpoints)
  if (req.method === 'GET' && !req.path.includes('/api/notifications') && !req.path.includes('/api/messages')) {
    res.set('Cache-Control', 'public, max-age=300'); // 5 minutes
  }
  next();
});

// MongoDB connection URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ivo4yuq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: false,
    deprecationErrors: true,
  },
  // Performance: Connection pool optimization
  maxPoolSize: 50, // Maximum number of connections in the pool
  minPoolSize: 10, // Minimum number of connections
  maxIdleTimeMS: 30000, // Close connections after 30 seconds of inactivity
  serverSelectionTimeoutMS: 30000, // Increased timeout for VPS (30 seconds)
  connectTimeoutMS: 30000, // Connection timeout (30 seconds)
  socketTimeoutMS: 45000, // Socket timeout (45 seconds)
  // Retry configuration
  retryWrites: true,
  retryReads: true,
  // DNS resolution
  directConnection: false, // Use SRV records for MongoDB Atlas
});

// (audio upload route is defined after audioUpload is initialized)

// MongoDB connection
let isConnected = false;
let connectionPromise = null;
let connectionRetries = 0;
const MAX_RETRIES = 3;
const RETRY_DELAY = 2000; // 2 seconds

async function connectToMongo() {
  // If already connected, verify it's still alive
  if (isConnected) {
    try {
      await client.db("admin").command({ ping: 1 });
      return;
    } catch (error) {
      console.log("MongoDB connection lost, reconnecting...");
      isConnected = false;
      connectionPromise = null;
      connectionRetries = 0;
    }
  }
  
  // If connection is in progress, wait for it
  if (connectionPromise) {
    return connectionPromise;
  }
  
  // Start new connection with retry logic
  connectionPromise = (async () => {
    let lastError = null;
    
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      try {
        // Check if credentials are available
        if (!process.env.DB_USER || !process.env.DB_PASS) {
          throw new Error("MongoDB credentials (DB_USER or DB_PASS) are missing in environment variables");
        }
        
        // Close existing connection if it exists but is not working
        if (client.topology && client.topology.isConnected()) {
          try {
            await client.db("admin").command({ ping: 1 });
            isConnected = true;
            connectionPromise = null;
            connectionRetries = 0;
            console.log("✅ MongoDB connection verified.");
            return;
          } catch (pingError) {
            console.log("Existing connection failed ping, reconnecting...");
            try {
              await client.close();
            } catch (closeError) {
              // Ignore close errors
            }
          }
        }
        
        // Attempt to connect
        if (!client.topology || !client.topology.isConnected()) {
          console.log(`Attempting MongoDB connection (attempt ${attempt + 1}/${MAX_RETRIES + 1})...`);
          await client.connect();
        }
        
        // Verify connection with timeout (increased for VPS)
        const pingPromise = client.db("admin").command({ ping: 1 });
        const timeoutPromise = new Promise((_, reject) => 
          setTimeout(() => reject(new Error("Connection ping timeout")), 30000)
        );
        
        await Promise.race([pingPromise, timeoutPromise]);
        
        // Connection successful
        isConnected = true;
        connectionPromise = null;
        connectionRetries = 0;
        console.log("✅ MongoDB connected successfully.");
        return;
        
      } catch (error) {
        lastError = error;
        connectionRetries = attempt + 1;
        
        // Log detailed error information
        console.error(`❌ MongoDB connection attempt ${attempt + 1} failed:`, {
          message: error.message,
          name: error.name,
          code: error.code,
          codeName: error.codeName
        });
        
        // If this is not the last attempt, wait before retrying
        if (attempt < MAX_RETRIES) {
          const delay = RETRY_DELAY * Math.pow(2, attempt); // Exponential backoff
          console.log(`⏳ Retrying in ${delay}ms...`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    
    // All retries failed
    isConnected = false;
    connectionPromise = null;
    const errorMessage = lastError?.message || "Unknown connection error";
    console.error(`❌ MongoDB connection failed after ${MAX_RETRIES + 1} attempts:`, errorMessage);
    
    // Provide helpful error message with VPS-specific guidance
    let userMessage = `Database connection failed: ${errorMessage}`;
    if (errorMessage.includes("authentication") || errorMessage.includes("credentials")) {
      userMessage = "Database authentication failed. Please check DB_USER and DB_PASS environment variables.";
    } else if (errorMessage.includes("timeout") || errorMessage.includes("Server selection timed out")) {
      userMessage = "Database connection timeout. This usually means:\n" +
        "1. VPS IP address is not whitelisted in MongoDB Atlas Network Access\n" +
        "2. Network/firewall blocking MongoDB Atlas (port 27017)\n" +
        "3. DNS resolution issues\n" +
        "Please check MongoDB Atlas Network Access settings and whitelist your VPS IP address (0.0.0.0/0 for testing).";
    } else if (errorMessage.includes("ENOTFOUND")) {
      userMessage = "DNS resolution failed. Cannot resolve MongoDB Atlas hostname. Check network connectivity.";
    }
    
    console.error("🔍 Troubleshooting steps:");
    console.error("   1. Check MongoDB Atlas Network Access - whitelist VPS IP or use 0.0.0.0/0 (for testing)");
    console.error("   2. Verify DB_USER and DB_PASS environment variables are set correctly");
    console.error("   3. Test network connectivity: ping cluster0.ivo4yuq.mongodb.net");
    console.error("   4. Check VPS firewall rules allow outbound connections on port 27017");
    
    throw new Error(userMessage);
  })();
  
  return connectionPromise;
}

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Helper function to upload buffer to Cloudinary
const uploadBufferToCloudinary = (buffer, fileName) => {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        resource_type: "raw",
        public_id: fileName,
        folder: "certificates",
        format: "pdf",
      },
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      }
    );
    const bufferStream = new stream.PassThrough();
    bufferStream.end(buffer);
    bufferStream.pipe(uploadStream);
  });
};

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

// Video storage configuration for Cloudinary
const videoStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: async (req, file) => {
    return {
      folder: "courseVideos",
      resource_type: "video",
      format: "mp4",
      public_id: `video_${Date.now()}_${file.originalname.replace(/\.[^/.]+$/, "")}`,
      transformation: [{ quality: "auto", fetch_format: "auto" }],
    };
  },
});

const videoUpload = multer({
  storage: videoStorage,
  limits: {
    fileSize: 200 * 1024 * 1024, // 200MB limit for videos
  },
  fileFilter: (req, file, cb) => {
    // Accept video files only
    if (file.mimetype.startsWith("video/")) {
      cb(null, true);
    } else {
      cb(new Error("Only video files are allowed!"), false);
    }
  },
});

// Audio storage configuration (Cloudinary treats audio under resource_type "video")
const audioStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: async (req, file) => {
    return {
      folder: "courseAudio",
      resource_type: "video",
      public_id: `audio_${Date.now()}_${file.originalname.replace(/\.[^/.]+$/, "")}`,
      // Let Cloudinary auto-detect audio format
      transformation: [{ quality: "auto" }],
    };
  },
});

const audioUpload = multer({
  storage: audioStorage,
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit for audio
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("audio/")) {
      cb(null, true);
    } else {
      cb(new Error("Only audio files are allowed!"), false);
    }
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

// Simple health check endpoint (no database needed)
app.get("/health", (req, res) => {
  res.json({ 
    status: "ok", 
    server: "running",
    timestamp: new Date().toISOString(),
    database: isConnected ? "connected" : "disconnected"
  });
});

// Middleware to connect to MongoDB before every route
// Skip database connection for routes that don't need it
app.use(async (req, res, next) => {
  // Skip database connection for static files and health check routes
  if (req.path === "/" || 
      req.path === "/health" || 
      req.path === "/diagnostics" ||
      req.path === "/favicon.ico" ||
      req.path.startsWith("/static/") ||
      req.path.startsWith("/assets/")) {
    return next();
  }
  
  // For critical endpoints with cache, skip middleware - let them handle their own fallback
  if (req.path === "/all-home-books" || req.path === "/home-category") {
    return next(); // These endpoints have their own fallback logic
  }
  
  try {
    await connectToMongo();
    next();
  } catch (error) {
    console.error(`MongoDB connection error for ${req.method} ${req.path}:`, error.message);
    
    // For presentation: Return empty data instead of error for most endpoints
    // This prevents frontend crashes
    if (req.method === "GET") {
      // Return empty array/object instead of error
      if (req.path.includes("/friends") || req.path.includes("/users")) {
        return res.json([]);
      }
      if (req.path.includes("/profile")) {
        return res.status(503).json({ 
          error: "Service temporarily unavailable",
          message: "Database connection failed. Please try again later."
        });
      }
    }
    
    // Provide more detailed error response
    const errorResponse = {
      message: error.message || "Failed to connect to database",
      path: req.path,
      method: req.method,
      timestamp: new Date().toISOString()
    };
    
    // Don't expose internal error details in production
    if (process.env.NODE_ENV === "development") {
      errorResponse.stack = error.stack;
    }
    
    res.status(500).json(errorResponse);
  }
});

// Edit a post (author or community admins/editors)
app.put("/posts/:postId", verifyTokenEarly, async (req, res) => {
  try {
    let postObjId;
    try { postObjId = new ObjectId(req.params.postId); } catch {
      return res.status(400).json({ success: false, message: "Invalid post id" });
    }

    const post = await communityPostsCollection.findOne({ _id: postObjId });
    if (!post) return res.status(404).json({ success: false, message: "Post not found" });

    // Permission: author or community admins/editors
    const role = await getCommunityRole(req.user._id, post.communityId.toString());
    const isAuthor = post.authorId?.toString() === req.user._id?.toString();
    if (!(isAuthor || role.isMainAdmin || role.isAdmin || role.isEditor)) {
      return res.status(403).json({ success: false, message: "Insufficient permissions" });
    }

    const allowed = ["title", "description", "visibility", "accessCode"]; // common fields
    // Allow content edit for non-course posts
    if (post.type !== "course") allowed.push("content");
    const $set = {};
    for (const k of allowed) {
      if (k in req.body) $set[k] = req.body[k];
    }
    if (!Object.keys($set).length) {
      return res.status(400).json({ success: false, message: "No updatable fields provided" });
    }

    await communityPostsCollection.updateOne({ _id: postObjId }, { $set });
    const updated = await communityPostsCollection.findOne({ _id: postObjId });
    return res.json({ success: true, data: updated });
  } catch (error) {
    console.error("PUT /posts/:postId error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Delete a post (author or community admins/editors) with cascade cleanup
app.delete("/posts/:postId", verifyTokenEarly, async (req, res) => {
  try {
    let postObjId;
    try { postObjId = new ObjectId(req.params.postId); } catch {
      return res.status(400).json({ success: false, message: "Invalid post id" });
    }

    const post = await communityPostsCollection.findOne({ _id: postObjId });
    if (!post) return res.status(404).json({ success: false, message: "Post not found" });

    const role = await getCommunityRole(req.user._id, post.communityId.toString());
    const isAuthor = post.authorId?.toString() === req.user._id?.toString();
    if (!(isAuthor || role.isMainAdmin || role.isAdmin || role.isEditor)) {
      return res.status(403).json({ success: false, message: "Insufficient permissions" });
    }

    // Cascade: delete likes
    await communityPostLikesCollection.deleteMany({ postId: postObjId });

    // If course post, cleanup related collections
    if (post.type === "course") {
      const course = await communityCoursesCollection.findOne({ postId: postObjId });
      if (course) {
        const courseId = course._id;
        await Promise.all([
          communityLessonsCollection.deleteMany({ courseId }),
          communityChaptersCollection.deleteMany({ courseId }),
          communityExamsCollection.deleteMany({ courseId }),
          communityExamAttemptsCollection.deleteMany({ courseId }),
          communityEnrollmentsCollection.deleteMany({ courseId }),
          communityProgressCollection.deleteMany({ courseId }),
          communityCertificatesCollection.deleteMany({ courseId }),
        ]);
        await communityCoursesCollection.deleteOne({ _id: courseId });
      }
    }

    await communityPostsCollection.deleteOne({ _id: postObjId });
    return res.json({ success: true });
  } catch (error) {
    console.error("DELETE /posts/:postId error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Upload audio (listening responses) to Cloudinary
app.post("/upload/audio", audioUpload.single("audio"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: "No audio file uploaded" });
    }

    const audioUrl = req.file.path; // Cloudinary URL
    const publicId = req.file.filename;

    return res.status(200).json({
      success: true,
      message: "Audio uploaded successfully",
      audioUrl,
      publicId,
      format: req.file.format || null,
      duration: req.file.duration || null,
    });
  } catch (error) {
    console.error("POST /upload/audio error:", error);
    return res.status(500).json({ success: false, message: "Failed to upload audio" });
  }
});

// List attempts for a specific course for grading dashboard (owner/admin only)
app.get("/courses/:courseId/attempts", verifyTokenEarly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const { graded } = req.query; // optional: 'true' | 'false'

    let courseObjId;
    try { courseObjId = new ObjectId(courseId); } catch {
      return res.status(400).json({ success: false, message: "Invalid course id" });
    }

    // Load course and post to determine owner and community
    const course = await communityCoursesCollection.findOne({ _id: courseObjId }, { projection: { postId: 1, communityId: 1 } });
    if (!course) return res.status(404).json({ success: false, message: "Course not found" });
    const post = await communityPostsCollection.findOne({ _id: course.postId }, { projection: { authorId: 1 } });
    if (!post) return res.status(404).json({ success: false, message: "Course post not found" });

    const isOwner = post.authorId?.toString() === req.user._id?.toString();
    const role = await getCommunityRole(req.user._id, course.communityId.toString());
    const isCommunityAdmin = role.isMainAdmin || role.isAdmin;
    if (!isOwner && !isCommunityAdmin) {
      return res.status(403).json({ success: false, message: "Not authorized to view attempts for this course" });
    }

    const query = { courseId: courseObjId, type: { $in: ['written', 'listening'] } };
    if (graded === 'true') query.graded = true;
    if (graded === 'false') query.graded = false;

    const attempts = await communityExamAttemptsCollection
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();

    // Join with user and exam details for context
    const enriched = await Promise.all(attempts.map(async (att) => {
      const user = await usersCollections.findOne({ _id: att.userId }, { projection: { name: 1, number: 1 } });
      const exam = await communityExamsCollection.findOne({ _id: att.examId }, { projection: { type: 1, passingScore: 1, chapterId: 1 } });
      return { ...att, user, exam };
    }));

    return res.json({ success: true, data: enriched });
  } catch (error) {
    console.error("GET /courses/:courseId/attempts error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Get comprehensive student dashboard statistics for a course (owner/admin only)
app.get("/courses/:courseId/student-dashboard", verifyTokenEarly, async (req, res) => {
  try {
    const { courseId } = req.params;
    let courseObjId;
    try { courseObjId = new ObjectId(courseId); } catch {
      return res.status(400).json({ success: false, message: "Invalid course id" });
    }

    // Load course and post to determine owner and community
    const course = await communityCoursesCollection.findOne({ _id: courseObjId }, { projection: { postId: 1, communityId: 1, title: 1 } });
    if (!course) return res.status(404).json({ success: false, message: "Course not found" });
    const post = await communityPostsCollection.findOne({ _id: course.postId }, { projection: { authorId: 1 } });
    if (!post) return res.status(404).json({ success: false, message: "Course post not found" });

    // Check authorization
    const isOwner = post.authorId?.toString() === req.user._id?.toString();
    const role = await getCommunityRole(req.user._id, course.communityId.toString());
    const isCommunityAdmin = role.isMainAdmin || role.isAdmin;
    if (!isOwner && !isCommunityAdmin) {
      return res.status(403).json({ success: false, message: "Not authorized to view student dashboard for this course" });
    }

    // Get all exam attempts for this course
    const allAttempts = await communityExamAttemptsCollection
      .find({ courseId: courseObjId })
      .sort({ createdAt: -1 })
      .toArray();

    // Get all exams for this course
    const exams = await communityExamsCollection.find({ courseId: courseObjId }).toArray();
    const chapters = await communityChaptersCollection.find({ courseId: courseObjId }).sort({ order: 1 }).toArray();

    // Get unique students who attempted exams
    const studentIds = [...new Set(allAttempts.map(att => att.userId.toString()))];
    const students = await usersCollections.find({ _id: { $in: studentIds.map(id => new ObjectId(id)) } })
      .project({ _id: 1, name: 1, number: 1, profileImage: 1 })
      .toArray();

    // Get all course progress records
    const progressRecords = await communityProgressCollection.find({ courseId: courseObjId }).toArray();

    // Build student statistics
    const studentStats = students.map(student => {
      const studentAttempts = allAttempts.filter(att => att.userId.toString() === student._id.toString());
      const studentProgress = progressRecords.find(p => p.userId.toString() === student._id.toString());

      // Group attempts by exam
      const attemptsByExam = {};
      studentAttempts.forEach(att => {
        const examId = att.examId.toString();
        if (!attemptsByExam[examId]) attemptsByExam[examId] = [];
        attemptsByExam[examId].push(att);
      });

      // Calculate statistics
      const totalAttempts = studentAttempts.length;
      const gradedAttempts = studentAttempts.filter(att => att.graded === true);
      const passedAttempts = gradedAttempts.filter(att => att.passed === true);
      const failedAttempts = gradedAttempts.filter(att => att.passed === false);
      const pendingGrading = studentAttempts.filter(att => att.graded === false);

      // Calculate average score (only for graded attempts with scores)
      const scoredAttempts = gradedAttempts.filter(att => att.score !== null && att.score !== undefined);
      const averageScore = scoredAttempts.length > 0 
        ? Math.round(scoredAttempts.reduce((sum, att) => sum + att.score, 0) / scoredAttempts.length)
        : null;

      // Get latest attempt for each exam with full details
      const examResults = exams.map(exam => {
        const examAttempts = attemptsByExam[exam._id.toString()] || [];
        const latestAttempt = examAttempts.length > 0 ? examAttempts[0] : null;
        const chapter = chapters.find(ch => ch._id.toString() === exam.chapterId.toString());

        return {
          examId: exam._id,
          examType: exam.type,
          chapterTitle: chapter?.title || 'Unknown Chapter',
          chapterOrder: chapter?.order || 0,
          attemptCount: examAttempts.length,
          // Include exam questions for display
          examQuestions: exam.questions || [],
          passingScore: exam.passingScore || 0,
          latestAttempt: latestAttempt ? {
            attemptId: latestAttempt._id,
            score: latestAttempt.score,
            passed: latestAttempt.passed,
            graded: latestAttempt.graded,
            createdAt: latestAttempt.createdAt,
            correctAnswers: latestAttempt.correctAnswers,
            totalQuestions: latestAttempt.totalQuestions,
            // Include full answers for display
            answers: latestAttempt.answers || [],
            audioUrl: latestAttempt.audioUrl || null,
            feedback: latestAttempt.feedback || null,
          } : null
        };
      });

      // Course completion status
      const completedLessons = studentProgress?.completedLessons?.length || 0;
      const hasCertificate = studentProgress?.certificateIssued || false;

      return {
        student: {
          id: student._id,
          name: student.name,
          number: student.number,
          profileImage: student.profileImage,
        },
        statistics: {
          totalAttempts,
          passedAttempts: passedAttempts.length,
          failedAttempts: failedAttempts.length,
          pendingGrading: pendingGrading.length,
          averageScore,
          completedLessons,
          hasCertificate,
        },
        examResults,
        lastActivity: studentAttempts.length > 0 ? studentAttempts[0].createdAt : null,
      };
    });

    // Overall course statistics
    const overallStats = {
      totalStudents: students.length,
      totalAttempts: allAttempts.length,
      totalExams: exams.length,
      totalChapters: chapters.length,
      gradedAttempts: allAttempts.filter(att => att.graded === true).length,
      pendingGrading: allAttempts.filter(att => att.graded === false).length,
      passRate: allAttempts.filter(att => att.graded === true).length > 0
        ? Math.round((allAttempts.filter(att => att.passed === true).length / allAttempts.filter(att => att.graded === true).length) * 100)
        : 0,
      certificatesIssued: progressRecords.filter(p => p.certificateIssued === true).length,
    };

    return res.json({
      success: true,
      data: {
        courseId: course._id,
        courseTitle: course.title,
        overallStats,
        students: studentStats,
      }
    });
  } catch (error) {
    console.error("GET /courses/:courseId/student-dashboard error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// List communities created by the current user
app.get("/my-communities", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }
    let user;
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      user = await usersCollections.findOne({ number: decoded.number });
    } catch (e) {
      return res.status(401).json({ success: false, message: "Invalid token" });
    }
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const mine = await communityCollection
      .find({ createdBy: user._id })
      .sort({ createdAt: -1 })
      .project({
        name: 1,
        description: 1,
        logo: 1,
        coverImage: 1,
        membersCount: 1,
        category: 1,
        isVerified: 1,
      })
      .toArray();

    return res.json({ success: true, data: mine });
  } catch (error) {
    console.error("GET /my-communities error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Get current user's permissions in a community
app.get("/communities/:id/permissions", verifyTokenEarly, async (req, res) => {
  try {
    let communityObjId;
    try {
      communityObjId = new ObjectId(req.params.id);
    } catch (_) {
      return res.status(400).json({ success: false, message: "Invalid community id" });
    }
    const role = await getCommunityRole(req.user._id, communityObjId.toString());
    if (!role.exists) return res.status(404).json({ success: false, message: "Community not found" });
    return res.json({ success: true, data: role });
  } catch (error) {
    console.error("GET /communities/:id/permissions error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Add a role (admin/editor) to a user in a community (mainAdmin only)
app.post("/communities/:id/roles/add", verifyTokenEarly, async (req, res) => {
  try {
    let communityObjId;
    try {
      communityObjId = new ObjectId(req.params.id);
    } catch (_) {
      return res.status(400).json({ success: false, message: "Invalid community id" });
    }
    const { userId, role } = req.body; // role: 'admin' | 'editor'
    if (!userId || !role || !["admin", "editor"].includes(role)) {
      return res.status(400).json({ success: false, message: "userId and valid role required" });
    }
    let userObjId;
    try {
      userObjId = new ObjectId(userId);
    } catch (_) {
      return res.status(400).json({ success: false, message: "Invalid userId" });
    }

    const community = await communityCollection.findOne({ _id: communityObjId });
    if (!community) return res.status(404).json({ success: false, message: "Community not found" });
    if (community.mainAdmin?.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, message: "Only mainAdmin can manage roles" });
    }

    if (role === "admin") {
      await communityCollection.updateOne(
        { _id: communityObjId },
        { $addToSet: { admins: userObjId }, $pull: { editors: userObjId } }
      );
    } else {
      await communityCollection.updateOne(
        { _id: communityObjId },
        { $addToSet: { editors: userObjId }, $pull: { admins: userObjId } }
      );
    }
    return res.json({ success: true });
  } catch (error) {
    console.error("POST /communities/:id/roles/add error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Remove a role (admin/editor) from a user (mainAdmin only)
app.post("/communities/:id/roles/remove", verifyTokenEarly, async (req, res) => {
  try {
    let communityObjId;
    try {
      communityObjId = new ObjectId(req.params.id);
    } catch (_) {
      return res.status(400).json({ success: false, message: "Invalid community id" });
    }
    const { userId, role } = req.body; // role: 'admin' | 'editor'
    if (!userId || !role || !["admin", "editor"].includes(role)) {
      return res.status(400).json({ success: false, message: "userId and valid role required" });
    }
    let userObjId;
    try {
      userObjId = new ObjectId(userId);
    } catch (_) {
      return res.status(400).json({ success: false, message: "Invalid userId" });
    }

    const community = await communityCollection.findOne({ _id: communityObjId });
    if (!community) return res.status(404).json({ success: false, message: "Community not found" });
    if (community.mainAdmin?.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, message: "Only mainAdmin can manage roles" });
    }

    if (role === "admin") {
      await communityCollection.updateOne(
        { _id: communityObjId },
        { $pull: { admins: userObjId } }
      );
    } else {
      await communityCollection.updateOne(
        { _id: communityObjId },
        { $pull: { editors: userObjId } }
      );
    }
    return res.json({ success: true });
  } catch (error) {
    console.error("POST /communities/:id/roles/remove error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});


// Get community detail
// (moved below after DB collection declarations)

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
const JWT_SECRET = process.env.ACCESS_TOKEN_SECRET || process.env.JWT_SECRET;

// Validate required environment variables on startup
if (!JWT_SECRET) {
  console.error("⚠️  WARNING: JWT_SECRET or ACCESS_TOKEN_SECRET is not set in environment variables!");
  console.error("⚠️  Authentication will fail without this variable.");
}

if (!process.env.DB_USER || !process.env.DB_PASS) {
  console.error("⚠️  WARNING: DB_USER or DB_PASS is not set in environment variables!");
  console.error("⚠️  Database connection will fail without these variables.");
}
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
const communityCollection = db.collection("communityCollection");
const communityFollowsCollection = db.collection("communityFollowsCollection");
const communityCoursesCollection = db.collection("communityCoursesCollection");
const communityChaptersCollection = db.collection(
  "communityChaptersCollection"
);
const communityLessonsCollection = db.collection("communityLessonsCollection");
const communityExamsCollection = db.collection("communityExamsCollection");
const communityExamAttemptsCollection = db.collection(
  "communityExamAttemptsCollection"
);
const communityCertificatesCollection = db.collection(
  "communityCertificatesCollection"
);
const communityPostsCollection = db.collection("communityPostsCollection");
const communityPostLikesCollection = db.collection("communityPostLikesCollection");
const communityProgressCollection = db.collection(
  "communityProgressCollection"
);
const communityEnrollmentsCollection = db.collection(
  "communityEnrollmentsCollection"
);
// Jobs & Employment collections
const jobsCollection = db.collection("jobsCollection");
const jobApplicationsCollection = db.collection("jobApplicationsCollection");
const employersCollection = db.collection("employersCollection");
// Freelance Marketplace collections
const projectsCollection = db.collection("projectsCollection");
const proposalsCollection = db.collection("proposalsCollection");
// Create text index on opinions collection when the server starts

const HUGGING_FACE_API_KEY = process.env.HUGGING_FACE_API_KEY;
const GOOGLE_API_KEY = process.env.GOOGLE_CUSTOM_SEARCH_API_KEY;
const SEARCH_ENGINE_ID = process.env.GOOGLE_CUSTOM_SEARCH_ENGINE_ID;
const GMINI_API_KEY = process.env.GMINI_API_KEY;

// Performance: Create all database indexes on startup
(async () => {
  try {
    await connectToMongo();
    
    // Text search index for opinions
    await opinionCollections.createIndex({ description: "text" });
    console.log("✅ Text index created for opinions");
    
    // Location index for books
    await bookCollections.createIndex({ location: "2dsphere" });
    console.log("✅ Location index created for books");
    
    // Performance: Indexes for frequently queried fields
    await usersCollections.createIndex({ number: 1 }, { unique: true });
    await usersCollections.createIndex({ email: 1 });
    await usersCollections.createIndex({ _id: 1, isOnline: 1 }); // For online status queries
    
    await messagesCollections.createIndex({ receiverId: 1, isRead: 1 });
    await messagesCollections.createIndex({ senderId: 1, receiverId: 1, timestamp: -1 });
    
    await notifyCollections.createIndex({ receiverId: 1, isRead: 1 });
    await notifyCollections.createIndex({ receiverId: 1, timestamp: -1 });
    
    await bookCollections.createIndex({ owner: 1 });
    await bookCollections.createIndex({ bookName: 1 });
    
    await pdfCollections.createIndex({ bookName: 1 });
    await pdfCollections.createIndex({ writerName: 1 });
    
    await opinionCollections.createIndex({ userName: 1 });
    
    await productsCollection.createIndex({ category: 1, status: 1 });
    await productsCollection.createIndex({ title: "text", description: "text" });
    
    await jobsCollection.createIndex({ status: 1, createdAt: -1 });
    await jobsCollection.createIndex({ title: "text", description: "text" });
    
    await projectsCollection.createIndex({ status: 1, createdAt: -1 });
    await projectsCollection.createIndex({ title: "text", description: "text" });
    
    await communityPostsCollection.createIndex({ communityId: 1, createdAt: -1 });
    await communityPostsCollection.createIndex({ authorId: 1 });
    
    await coursesCollection.createIndex({ status: 1 });
    await coursesCollection.createIndex({ title: "text" });
    
    // Indexes for admin posts (home page)
    await adminPostCollections.createIndex({ category: 1 });
    await adminPostCollections.createIndex({ date: -1, time: -1 }); // For sorting
    await adminPostCollections.createIndex({ createdAt: -1 }); // Fallback sorting
    
    console.log("✅ All database indexes created successfully!");
  } catch (error) {
    console.error("❌ Error creating indexes:", error);
  }
})();

// Route to check API status
app.get("/", (req, res) => {
  res.send("API is running!");
});

// Health check endpoint with database status
app.get("/health", async (req, res) => {
  try {
    await connectToMongo();
    await client.db("admin").command({ ping: 1 });
    
    // Test collections access
    const db = client.db("flybook");
    const testCollection = db.collection("usersCollections");
    await testCollection.findOne({}, { limit: 1 });
    
    res.json({
      status: "healthy",
      database: "connected",
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(503).json({
      status: "unhealthy",
      database: "disconnected",
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Diagnostic endpoint for VPS connection issues
app.get("/diagnostics", async (req, res) => {
  const diagnostics = {
    timestamp: new Date().toISOString(),
    environment: {
      nodeEnv: process.env.NODE_ENV || "not set",
      hasDbUser: !!process.env.DB_USER,
      hasDbPass: !!process.env.DB_PASS,
      mongoUri: process.env.DB_USER ? `mongodb+srv://${process.env.DB_USER}:***@cluster0.ivo4yuq.mongodb.net/` : "not configured"
    },
    connection: {
      isConnected: isConnected,
      hasConnectionPromise: !!connectionPromise,
      retries: connectionRetries
    },
    network: {
      mongoHost: "cluster0.ivo4yuq.mongodb.net",
      note: "Check if this host is reachable from VPS: ping cluster0.ivo4yuq.mongodb.net"
    },
    recommendations: []
  };
  
  // Test connection
  try {
    await connectToMongo();
    diagnostics.connection.test = "success";
    diagnostics.status = "✅ Connection successful";
  } catch (error) {
    diagnostics.connection.test = "failed";
    diagnostics.connection.error = error.message;
    diagnostics.status = "❌ Connection failed";
    
    if (error.message.includes("timeout") || error.message.includes("Server selection")) {
      diagnostics.recommendations.push("1. Check MongoDB Atlas Network Access - whitelist VPS IP address");
      diagnostics.recommendations.push("2. For testing, you can temporarily allow 0.0.0.0/0 (all IPs) in MongoDB Atlas");
      diagnostics.recommendations.push("3. Check VPS firewall: sudo ufw status (should allow outbound on port 27017)");
      diagnostics.recommendations.push("4. Test DNS: nslookup cluster0.ivo4yuq.mongodb.net");
    }
    
    if (!process.env.DB_USER || !process.env.DB_PASS) {
      diagnostics.recommendations.push("5. Set DB_USER and DB_PASS environment variables in PM2 or .env file");
    }
  }
  
  res.json(diagnostics);
});

// =====================
// Community: Posts, Courses, Exams, Certificates
// =====================

// Early auth middleware for community routes (defined here to avoid reference order issues)
async function verifyTokenEarly(req, res, next) {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Unauthorized: Token missing" });
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res.status(403).json({ message: "No User Founded" });
    }
    req.user = user;
    next();
  } catch (err) {
    console.error("Auth error:", err);
    return res.status(401).json({ message: "Unauthorized: Invalid token" });
  }
}

// Helper: role check inside a community
async function getCommunityRole(userId, communityId) {
  const comm = await communityCollection.findOne({ _id: new ObjectId(communityId) });
  if (!comm) return { exists: false };
  const uid = userId?.toString();
  const isMainAdmin = comm.mainAdmin?.toString() === uid;
  const isAdmin = comm.admins?.some((x) => x.toString() === uid);
  const isEditor = comm.editors?.some((x) => x.toString() === uid);
  return { exists: true, isMainAdmin, isAdmin, isEditor };
}

// Create a post in a community (text | video | course)
app.post("/communities/:id/posts", verifyTokenEarly, async (req, res) => {
  try {
    const communityId = req.params.id;
    let communityObjId;
    try {
      communityObjId = new ObjectId(communityId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid community id" });
    }

    const { title, description, type, content, visibility = "public", accessCode = null, chapters = [] } = req.body;
    if (!title || !type) {
      return res.status(400).json({ success: false, message: "title and type are required" });
    }

    // Role enforcement: main admin/admin/editor can create posts
    const role = await getCommunityRole(req.user._id, communityId);
    if (!role.exists) return res.status(404).json({ success: false, message: "Community not found" });
    if (!(role.isMainAdmin || role.isAdmin || role.isEditor)) {
      return res.status(403).json({ success: false, message: "Insufficient permissions" });
    }

    const baseDoc = {
      communityId: communityObjId,
      authorId: req.user._id,
      title,
      description: description || "",
      type, // 'text' | 'video' | 'course'
      visibility, // 'public' | 'private'
      accessCode,
      likesCount: 0,
      createdAt: new Date(),
    };

    // For non-course posts
    if (type !== "course") {
      baseDoc.content = content; // string or [videoUrls]
      const result = await communityPostsCollection.insertOne(baseDoc);
      return res.status(201).json({ success: true, postId: result.insertedId });
    }

    // For course posts: create post, plus course/chapters/lessons/exams
    const postResult = await communityPostsCollection.insertOne({ ...baseDoc, content: null });
    const courseDoc = {
      postId: postResult.insertedId,
      communityId: communityObjId,
      title,
      createdAt: new Date(),
    };
    const courseResult = await communityCoursesCollection.insertOne(courseDoc);

    // Create chapters and lessons; chapters: [{ title, videos: [url], exam: {type, questions, passingScore} }]
    for (let idx = 0; idx < chapters.length; idx++) {
      const ch = chapters[idx];
      const chRes = await communityChaptersCollection.insertOne({
        courseId: courseResult.insertedId,
        order: idx + 1,
        title: ch.title || `Chapter ${idx + 1}`,
        createdAt: new Date(),
      });
      // lessons
      const videos = Array.isArray(ch.videos) ? ch.videos : [];
      for (let l = 0; l < videos.length; l++) {
        await communityLessonsCollection.insertOne({
          courseId: courseResult.insertedId,
          chapterId: chRes.insertedId,
          order: l + 1,
          videoUrl: videos[l],
          createdAt: new Date(),
        });
      }
      // optional exam
      if (ch.exam && ch.exam.type) {
        await communityExamsCollection.insertOne({
          postId: postResult.insertedId,
          courseId: courseResult.insertedId,
          chapterId: chRes.insertedId,
          type: ch.exam.type, // quiz | written | listening
          questions: Array.isArray(ch.exam.questions) ? ch.exam.questions : [],
          passingScore: Number(ch.exam.passingScore || 0),
          createdAt: new Date(),
        });
      }
    }

    return res.status(201).json({ success: true, postId: postResult.insertedId, courseId: courseResult.insertedId });
  } catch (error) {
    console.error("POST /communities/:id/posts error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Update community details (name, description, logo, coverImage) - mainAdmin only
app.patch("/communities/:id", verifyTokenEarly, async (req, res) => {
  try {
    let communityObjId;
    try {
      communityObjId = new ObjectId(req.params.id);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid community id" });
    }

    const community = await communityCollection.findOne({ _id: communityObjId });
    if (!community) return res.status(404).json({ success: false, message: "Community not found" });
    if (community.mainAdmin?.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, message: "Only owner can update community" });
    }

    const allowed = ["name", "description", "logo", "coverImage"];
    const $set = {};
    for (const k of allowed) {
      if (k in req.body) $set[k] = req.body[k];
    }
    if (!Object.keys($set).length) {
      return res.status(400).json({ success: false, message: "No updatable fields provided" });
    }

    await communityCollection.updateOne({ _id: communityObjId }, { $set });
    const updated = await communityCollection.findOne({ _id: communityObjId });
    return res.json({ success: true, data: updated });
  } catch (error) {
    console.error("PATCH /communities/:id error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Get posts of a community (public or private with accessCode)
app.get("/communities/:id/posts", async (req, res) => {
  try {
    const communityId = req.params.id;
    let communityObjId;
    try {
      communityObjId = new ObjectId(communityId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid community id" });
    }

    const { accessCode } = req.query;
    const query = { communityId: communityObjId };
    if (!accessCode) {
      query.visibility = "public";
    } else {
      // include private if code matches document's accessCode
      // fetch all and filter below for simplicity
    }

    const posts = await communityPostsCollection.find({ communityId: communityObjId }).sort({ createdAt: -1 }).toArray();

    const filtered = posts.filter((p) => {
      if (p.visibility === "public") return true;
      if (p.visibility === "private" && accessCode && accessCode === p.accessCode) return true;
      return false;
    });

    return res.json({ success: true, data: filtered });
  } catch (error) {
    console.error("GET /communities/:id/posts error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Map postId -> courseId
app.get("/posts/:postId/course", async (req, res) => {
  try {
    let postObjId;
    try {
      postObjId = new ObjectId(req.params.postId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid post id" });
    }
    const course = await communityCoursesCollection.findOne(
      { postId: postObjId },
      { projection: { _id: 1 } }
    );
    if (!course) return res.status(404).json({ success: false, message: "Course not found for this post" });
    return res.json({ success: true, courseId: course._id });
  } catch (error) {
    console.error("GET /posts/:postId/course error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Like/Unlike a post (toggle)
app.post("/posts/:postId/like", verifyTokenEarly, async (req, res) => {
  try {
    let postObjId;
    try {
      postObjId = new ObjectId(req.params.postId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid post id" });
    }

    const existing = await communityPostLikesCollection.findOne({
      postId: postObjId,
      userId: req.user._id,
    });

    if (existing) {
      // Unlike
      await communityPostLikesCollection.deleteOne({ _id: existing._id });
      await communityPostsCollection.updateOne(
        { _id: postObjId },
        { $inc: { likesCount: -1 } }
      );
      return res.json({ success: true, liked: false });
    } else {
      // Like
      await communityPostLikesCollection.insertOne({
        postId: postObjId,
        userId: req.user._id,
        createdAt: new Date(),
      });
      await communityPostsCollection.updateOne(
        { _id: postObjId },
        { $inc: { likesCount: 1 } }
      );
      return res.json({ success: true, liked: true });
    }
  } catch (error) {
    console.error("POST /posts/:postId/like error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Check if current user liked a post
app.get("/posts/:postId/liked", verifyTokenEarly, async (req, res) => {
  try {
    let postObjId;
    try {
      postObjId = new ObjectId(req.params.postId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid post id" });
    }
    const doc = await communityPostLikesCollection.findOne({
      postId: postObjId,
      userId: req.user._id,
    }, { projection: { _id: 1 } });
    return res.json({ success: true, liked: !!doc });
  } catch (error) {
    console.error("GET /posts/:postId/liked error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Self-enroll into a course
app.post("/courses/:courseId/enroll", verifyTokenEarly, async (req, res) => {
  try {
    let courseObjId;
    try {
      courseObjId = new ObjectId(req.params.courseId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid course id" });
    }
    const course = await communityCoursesCollection.findOne({ _id: courseObjId });
    if (!course) return res.status(404).json({ success: false, message: "Course not found" });

    await communityEnrollmentsCollection.updateOne(
      { userId: req.user._id, courseId: courseObjId },
      {
        $setOnInsert: {
          userId: req.user._id,
          courseId: courseObjId,
          postId: course.postId,
          communityId: course.communityId,
          role: "student",
          createdAt: new Date(),
        },
      },
      { upsert: true }
    );
    return res.status(201).json({ success: true });
  } catch (error) {
    console.error("POST /courses/:courseId/enroll error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Admin enroll another user
app.post("/courses/:courseId/enroll-user", verifyTokenEarly, async (req, res) => {
  try {
    let courseObjId;
    try {
      courseObjId = new ObjectId(req.params.courseId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid course id" });
    }
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ success: false, message: "userId required" });
    let userObjId;
    try {
      userObjId = new ObjectId(userId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid userId" });
    }

    const course = await communityCoursesCollection.findOne({ _id: courseObjId });
    if (!course) return res.status(404).json({ success: false, message: "Course not found" });

    const role = await getCommunityRole(req.user._id, course.communityId.toString());
    if (!(role.isMainAdmin || role.isAdmin || role.isEditor)) {
      return res.status(403).json({ success: false, message: "Insufficient permissions" });
    }

    await communityEnrollmentsCollection.updateOne(
      { userId: userObjId, courseId: courseObjId },
      {
        $setOnInsert: {
          userId: userObjId,
          courseId: courseObjId,
          postId: course.postId,
          communityId: course.communityId,
          role: "student",
          createdAt: new Date(),
        },
      },
      { upsert: true }
    );
    return res.status(201).json({ success: true });
  } catch (error) {
    console.error("POST /courses/:courseId/enroll-user error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Check if current user is enrolled in a course
app.get("/courses/:courseId/enrolled", verifyTokenEarly, async (req, res) => {
  try {
    let courseObjId;
    try {
      courseObjId = new ObjectId(req.params.courseId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid course id" });
    }
    const doc = await communityEnrollmentsCollection.findOne({ userId: req.user._id, courseId: courseObjId }, { projection: { _id: 1 } });
    return res.json({ success: true, enrolled: !!doc });
  } catch (error) {
    console.error("GET /courses/:courseId/enrolled error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Course outline
app.get("/courses/:courseId/outline", verifyTokenEarly, async (req, res) => {
  try {
    let courseObjId;
    try {
      courseObjId = new ObjectId(req.params.courseId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid course id" });
    }
    const course = await communityCoursesCollection.findOne(
      { _id: courseObjId },
      { projection: { _id: 1, title: 1, communityId: 1, postId: 1 } }
    );
    if (!course) return res.status(404).json({ success: false, message: "Course not found" });

    const chapters = await communityChaptersCollection.find({ courseId: courseObjId }).sort({ order: 1 }).toArray();
    const lessons = await communityLessonsCollection.find({ courseId: courseObjId }).sort({ chapterId: 1, order: 1 }).toArray();
    const exams = await communityExamsCollection.find({ courseId: courseObjId }).toArray();

    const examByChapter = new Map(exams.map((e) => [e.chapterId.toString(), e]));

    const outline = chapters.map((ch) => {
      const chLessons = lessons.filter((l) => l.chapterId.toString() === ch._id.toString());
      const ex = examByChapter.get(ch._id.toString());
      return {
        chapterId: ch._id,
        title: ch.title,
        order: ch.order,
        lessons: chLessons.map((l) => ({ lessonId: l._id, order: l.order, videoUrl: l.videoUrl })),
        exam: ex
          ? {
              examId: ex._id,
              type: ex.type,
              passingScore: ex.passingScore,
              questions: Array.isArray(ex.questions)
                ? ex.questions.map((q) => ({ question: q.question, options: q.options }))
                : [],
            }
          : null,
      };
    });

    return res.json({ success: true, data: { courseId: course._id, title: course.title, outline } });
  } catch (error) {
    console.error("GET /courses/:courseId/outline error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Course progress
app.get("/courses/:courseId/progress", verifyTokenEarly, async (req, res) => {
  try {
    let courseObjId;
    try {
      courseObjId = new ObjectId(req.params.courseId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid course id" });
    }
    const progress = await communityProgressCollection.findOne({ userId: req.user._id, courseId: courseObjId });
    const attempts = await communityExamAttemptsCollection
      .find({ userId: req.user._id, courseId: courseObjId })
      .project({ examId: 1, score: 1, passed: 1, createdAt: 1 })
      .sort({ createdAt: -1 })
      .toArray();
    return res.json({ success: true, data: { completedLessons: progress?.completedLessons || [], attempts } });
  } catch (error) {
    console.error("GET /courses/:courseId/progress error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Sanitized exam detail (no answers)
app.get("/exams/:examId", verifyTokenEarly, async (req, res) => {
  try {
    let examObjId;
    try {
      examObjId = new ObjectId(req.params.examId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid exam id" });
    }
    const ex = await communityExamsCollection.findOne({ _id: examObjId });
    if (!ex) return res.status(404).json({ success: false, message: "Exam not found" });
    const sanitized = {
      examId: ex._id,
      type: ex.type,
      passingScore: ex.passingScore,
      questions: Array.isArray(ex.questions) ? ex.questions.map((q) => ({ question: q.question, options: q.options })) : [],
    };
    return res.json({ success: true, data: sanitized });
  } catch (error) {
    console.error("GET /exams/:examId error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Mark lesson complete for a user
app.post("/courses/:courseId/lessons/:lessonId/complete", verifyTokenEarly, async (req, res) => {
  try {
    const { courseId, lessonId } = req.params;
    let courseObjId, lessonObjId;
    try {
      courseObjId = new ObjectId(courseId);
      lessonObjId = new ObjectId(lessonId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid id" });
    }

    const progressKey = { userId: req.user._id, courseId: courseObjId };
    await communityProgressCollection.updateOne(progressKey, {
      $addToSet: { completedLessons: lessonObjId },
      $setOnInsert: { createdAt: new Date() },
      $set: { updatedAt: new Date() },
    }, { upsert: true });

    return res.json({ success: true });
  } catch (error) {
    console.error("POST /courses/:courseId/lessons/:lessonId/complete error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Attempt an exam (auto-grade quiz type, manual grade for written/listening)
app.post("/exams/:examId/attempt", verifyTokenEarly, async (req, res) => {
  try {
    const { examId } = req.params;
    let examObjId;
    try {
      examObjId = new ObjectId(examId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid exam id" });
    }

    const exam = await communityExamsCollection.findOne({ _id: examObjId });
    if (!exam) return res.status(404).json({ success: false, message: "Exam not found" });

    const { answers, audioUrl, proctoring } = req.body; // answers: [{questionIndex, answer}], audioUrl for listening, proctoring summary

    // If client indicates submission must be blocked due to proctoring
    if (proctoring && proctoring.blockedSubmission === true) {
      return res.status(400).json({ success: false, message: "Submission blocked due to proctoring violations" });
    }

    // Quiz type: auto-grade
    if (exam.type === "quiz") {
      let score = 0;
      if (Array.isArray(exam.questions)) {
        for (let i = 0; i < exam.questions.length; i++) {
          const given = answers?.find((a) => a.questionIndex === i)?.answer;
          if (given && given === exam.questions[i].answer) score++;
        }
      }

      const totalQuestions = exam.questions?.length || 1;
      const percentageScore = Math.round((score / totalQuestions) * 100);
      const passingScoreThreshold = Number(exam.passingScore || 0);
      const passed = percentageScore >= passingScoreThreshold;
      
      const attemptDoc = {
        userId: req.user._id,
        examId: exam._id,
        courseId: exam.courseId,
        chapterId: exam.chapterId,
        postId: exam.postId,
        type: exam.type,
        answers,
        score: percentageScore,
        correctAnswers: score,
        totalQuestions,
        passed,
        graded: true,
        createdAt: new Date(),
        proctoring: proctoring || null,
      };
      const attemptRes = await communityExamAttemptsCollection.insertOne(attemptDoc);
      return res.status(201).json({ success: true, attemptId: attemptRes.insertedId, score: percentageScore, correctAnswers: score, passed });
    }

    // Written type: pending manual grading
    if (exam.type === "written") {
      const attemptDoc = {
        userId: req.user._id,
        examId: exam._id,
        courseId: exam.courseId,
        chapterId: exam.chapterId,
        postId: exam.postId,
        type: exam.type,
        answers, // Written answers
        score: null,
        passed: null,
        graded: false, // Needs manual grading
        createdAt: new Date(),
        proctoring: proctoring || null,
      };
      const attemptRes = await communityExamAttemptsCollection.insertOne(attemptDoc);
      return res.status(201).json({ success: true, attemptId: attemptRes.insertedId, message: "Submitted for grading", graded: false });
    }

    // Listening type: pending manual grading
    if (exam.type === "listening") {
      const attemptDoc = {
        userId: req.user._id,
        examId: exam._id,
        courseId: exam.courseId,
        chapterId: exam.chapterId,
        postId: exam.postId,
        type: exam.type,
        audioUrl, // Recorded audio URL
        answers, // Optional text answers
        score: null,
        passed: null,
        graded: false, // Needs manual grading
        createdAt: new Date(),
        proctoring: proctoring || null,
      };
      const attemptRes = await communityExamAttemptsCollection.insertOne(attemptDoc);
      return res.status(201).json({ success: true, attemptId: attemptRes.insertedId, message: "Submitted for grading", graded: false });
    }

    return res.status(400).json({ success: false, message: "Invalid exam type" });
  } catch (error) {
    console.error("POST /exams/:examId/attempt error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Grade a written/listening exam attempt (course owner or community admin only)
app.post("/exams/attempts/:attemptId/grade", verifyTokenEarly, async (req, res) => {
  try {
    const { attemptId } = req.params;
    const { score, feedback } = req.body;

    // Validate id
    let attemptObjId;
    try {
      attemptObjId = new ObjectId(attemptId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid attempt id" });
    }

    // Load attempt and exam
    const attempt = await communityExamAttemptsCollection.findOne({ _id: attemptObjId });
    if (!attempt) return res.status(404).json({ success: false, message: "Attempt not found" });

    const exam = await communityExamsCollection.findOne({ _id: attempt.examId });
    if (!exam) return res.status(404).json({ success: false, message: "Exam not found" });

    // Authorization: Only course owner (post author) or community admins can grade
    const course = await communityCoursesCollection.findOne({ _id: exam.courseId }, { projection: { communityId: 1, postId: 1 } });
    if (!course) return res.status(404).json({ success: false, message: "Course not found" });

    // Find the post to get the author (course owner)
    const post = await communityPostsCollection.findOne({ _id: course.postId }, { projection: { authorId: 1, communityId: 1 } });
    if (!post) return res.status(404).json({ success: false, message: "Course post not found" });

    const isOwner = post.authorId?.toString() === req.user._id?.toString();
    const role = await getCommunityRole(req.user._id, (post.communityId || course.communityId).toString());
    const isCommunityAdmin = role.isMainAdmin || role.isAdmin;
    if (!isOwner && !isCommunityAdmin) {
      return res.status(403).json({ success: false, message: "Not authorized to grade this attempt" });
    }

    // Only allow grading written/listening types
    if (!['written', 'listening'].includes(exam.type)) {
      return res.status(400).json({ success: false, message: "Only written/listening attempts require grading" });
    }

    const percentageScore = Math.max(0, Math.min(100, Number(score)));
    const passingScoreThreshold = Number(exam.passingScore || 0);
    const passed = percentageScore >= passingScoreThreshold;

    await communityExamAttemptsCollection.updateOne(
      { _id: attemptObjId },
      {
        $set: {
          score: percentageScore,
          passed,
          graded: true,
          feedback: feedback || "",
          gradedBy: req.user._id,
          gradedAt: new Date(),
        },
      }
    );

    return res.json({ success: true, score: percentageScore, passed });
  } catch (error) {
    console.error("POST /exams/attempts/:attemptId/grade error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Get ungraded attempts (platform-wide; internal/debug)
app.get("/exams/attempts/ungraded", verifyTokenEarly, async (req, res) => {
  try {
    const attempts = await communityExamAttemptsCollection
      .find({ graded: false })
      .sort({ createdAt: -1 })
      .toArray();

    // Populate user and exam details
    const enriched = await Promise.all(
      attempts.map(async (att) => {
        const user = await usersCollections.findOne({ _id: att.userId }, { projection: { name: 1, number: 1 } });
        const exam = await communityExamsCollection.findOne({ _id: att.examId }, { projection: { type: 1, questions: 1 } });
        return { ...att, user, exam };
      })
    );

    return res.json({ success: true, data: enriched });
  } catch (error) {
    console.error("GET /exams/attempts/ungraded error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Issue certificate when course completed (all lessons completed and all chapter exams passed where present)
app.post("/courses/:courseId/certificate", verifyTokenEarly, async (req, res) => {
  try {
    const { courseId } = req.params;
    let courseObjId;
    try {
      courseObjId = new ObjectId(courseId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid course id" });
    }

    // Validate completion
    const lessons = await communityLessonsCollection.find({ courseId: courseObjId }).project({ _id: 1 }).toArray();
    const lessonIds = lessons.map((l) => l._id.toString());
    const progress = await communityProgressCollection.findOne({ userId: req.user._id, courseId: courseObjId });
    const completed = new Set((progress?.completedLessons || []).map((x) => x.toString()));
    const allLessonsDone = lessonIds.every((id) => completed.has(id));

    // All exams passed
    const exams = await communityExamsCollection.find({ courseId: courseObjId }).project({ _id: 1 }).toArray();
    let allExamsPassed = true;
    for (const ex of exams) {
      const lastAttempt = await communityExamAttemptsCollection.find({ userId: req.user._id, examId: ex._id })
        .sort({ createdAt: -1 })
        .limit(1)
        .toArray();
      if (!lastAttempt[0]?.passed) { allExamsPassed = false; break; }
    }

    if (!allLessonsDone || !allExamsPassed) {
      return res.status(400).json({ success: false, message: "Course not completed yet" });
    }

    // Build beautiful PDF certificate
const doc = new PDFDocument({ 
  size: "A4", 
  layout: "landscape",
  margin: 0 
});
const chunks = [];
doc.on("data", (d) => chunks.push(d));
const done = new Promise((resolve) => doc.on("end", resolve));

// Get course details
const courseDoc = await communityCoursesCollection.findOne({ _id: courseObjId }, { 
  projection: { title: 1, description: 1 }
});

// Get user details
const userName = req.user.name || req.user.number;
const userEmail = req.user.email || "";

// Certificate ID
const certificateId = `CERT-${Date.now()}-${req.user._id.toString().slice(-6).toUpperCase()}`;
const issueDate = new Date().toLocaleDateString('en-US', { 
  year: 'numeric', 
  month: 'long', 
  day: 'numeric' 
});

// Page dimensions (A4 landscape)
const pageWidth = 842;
const pageHeight = 595;

// Background decorative elements first
doc.save();
doc.circle(pageWidth / 2, 80, 40)
   .fillColor('#eff6ff')
   .fill();
doc.restore();

// Decorative border
doc.save();
doc.rect(20, 20, pageWidth - 40, pageHeight - 40)
   .lineWidth(3)
   .strokeColor('#1e40af')
   .stroke();
doc.restore();

doc.save();
doc.rect(30, 30, pageWidth - 60, pageHeight - 60)
   .lineWidth(1)
   .strokeColor('#3b82f6')
   .stroke();
doc.restore();

// Top circle decoration
doc.save();
doc.circle(pageWidth / 2, 80, 35)
   .lineWidth(2)
   .strokeColor('#1e40af')
   .stroke();
doc.restore();

// Header - Certificate Title
doc.fontSize(42)
   .fillColor('#1e40af')
   .font('Helvetica-Bold')
   .text('CERTIFICATE', 0, 100, { align: 'center' });

doc.fontSize(28)
   .fillColor('#3b82f6')
   .text('OF COMPLETION', 0, 150, { align: 'center' });

// Decorative line
doc.save();
doc.moveTo(pageWidth / 2 - 150, 190)
   .lineTo(pageWidth / 2 + 150, 190)
   .lineWidth(2)
   .strokeColor('#fbbf24')
   .stroke();
doc.restore();

// "This is to certify that"
doc.fontSize(16)
   .fillColor('#4b5563')
   .font('Helvetica')
   .text('This is to certify that', 0, 220, { align: 'center' });

// User Name (highlighted)
doc.fontSize(36)
   .fillColor('#1e40af')
   .font('Helvetica-Bold')
   .text(userName, 0, 250, { align: 'center' });

// Underline for name
doc.moveTo(pageWidth / 2 - 200, 295)
   .lineTo(pageWidth / 2 + 200, 295)
   .lineWidth(1)
   .strokeColor('#3b82f6')
   .stroke();

// Achievement text
doc.fontSize(16)
   .fillColor('#4b5563')
   .font('Helvetica')
   .text('has successfully completed the course', 0, 315, { align: 'center' });

// Course Title (highlighted box)
const courseTitleY = 350;
doc.roundedRect(pageWidth / 2 - 250, courseTitleY - 10, 500, 50, 5)
   .fillColor('#eff6ff')
   .fill();

doc.fontSize(24)
   .fillColor('#1e40af')
   .font('Helvetica-Bold')
   .text(courseDoc?.title || "Course", 0, courseTitleY + 5, { 
     align: 'center',
     width: pageWidth
   });

// Certificate details section
const detailsY = 430;
doc.fontSize(12)
   .fillColor('#6b7280')
   .font('Helvetica');

// Certificate ID
doc.text(`Certificate ID: ${certificateId}`, 80, detailsY, { align: 'left' });

// Issue Date
doc.text(`Issue Date: ${issueDate}`, pageWidth - 280, detailsY, { align: 'left' });

// Footer decorative line
doc.moveTo(80, detailsY + 30)
   .lineTo(pageWidth - 80, detailsY + 30)
   .lineWidth(1)
   .strokeColor('#e5e7eb')
   .stroke();

// Platform name and signature area
doc.fontSize(14)
   .fillColor('#1e40af')
   .font('Helvetica-Bold')
   .text('FlyBook Learning Platform', 80, detailsY + 50, { align: 'left' });

// Signature line
doc.moveTo(pageWidth - 280, detailsY + 70)
   .lineTo(pageWidth - 80, detailsY + 70)
   .lineWidth(1)
   .strokeColor('#9ca3af')
   .stroke();

doc.fontSize(10)
   .fillColor('#6b7280')
   .font('Helvetica')
   .text('Authorized Signature', pageWidth - 280, detailsY + 75, { 
     align: 'center',
     width: 200
   });

// Bottom decorative corners
doc.circle(60, pageHeight - 60, 20)
   .fillColor('#fbbf24', 0.2)
   .fill();

doc.circle(pageWidth - 60, pageHeight - 60, 20)
   .fillColor('#3b82f6', 0.2)
   .fill();

doc.end();
await done;
const pdfBuffer = Buffer.concat(chunks);

// Upload to Cloudinary
const fileName = `cert_${req.user._id}_${courseId}_${Date.now()}`;
const upload = await uploadBufferToCloudinary(pdfBuffer, fileName);
const certificateUrl = upload.secure_url;

// Save record with URL and details
const certificateDoc = {
  userId: req.user._id,
  userName: userName,
  userEmail: userEmail,
  courseId: courseObjId,
  courseTitle: courseDoc?.title || "Course",
  certificateId: certificateId,
  issuedAt: new Date(),
  certificateUrl,
  publicId: upload.public_id,
};
const certRes = await communityCertificatesCollection.insertOne(certificateDoc);
return res.status(201).json({ 
  success: true, 
  certificateId: certRes.insertedId, 
  certificateUrl,
  certificateNumber: certificateId
});
  } catch (error) {
    console.error("POST /courses/:courseId/certificate error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Create Community (Main Admin = token owner)
app.post("/community-create", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  console.log("token", token);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log(decoded)
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }
    console.log("user", user);
    const { communityData } = req.body;
    console.log(communityData)
    if (!communityData?.name || !communityData?.description) {
      return res
        .status(400)
        .json({ success: false, message: "name and description are required" });
    }
    console.log("communityData", communityData);
    const doc = {
      name: communityData.name,
      description: communityData.description,
      category: communityData.category || "general",
      logo: communityData.logo || null,
      coverImage: communityData.coverImage || null,
      createdAt: new Date(),
      createdBy: user._id,
      mainAdmin: user._id,
      admins: [user._id],
      editors: [],
      membersCount: 1,
      privacy: communityData.privacy || "public", // public | private
      isVerified: false,
    };

    const result = await communityCollection.insertOne(doc);
    console.log("result", result);
    return res.status(201).json({ success: true, id: result.insertedId });
  } catch (error) {
    console.error("/community-create error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
});

// List Communities (followed-first if token provided)
app.get("/communities", async (req, res) => {
  try {
    let userId = null;
    const token = req.headers.authorization?.split(" ")[1];
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await usersCollections.findOne({ number: decoded.number });
        if (user) userId = user._id;
      } catch (_) {}
    }

    const communities = await communityCollection
      .find({})
      .project({
        name: 1,
        description: 1,
        category: 1,
        logo: 1,
        coverImage: 1,
        membersCount: 1,
        isVerified: 1,
      })
      .toArray();

    if (!userId) return res.json({ success: true, data: communities });

    const follows = await communityFollowsCollection
      .find({ userId })
      .project({ communityId: 1 })
      .toArray();
    const followedIds = new Set(follows.map((f) => f.communityId.toString()));

    const followed = [];
    const others = [];
    for (const c of communities) {
      if (followedIds.has(c._id.toString())) followed.push(c);
      else others.push(c);
    }
    return res.json({ success: true, data: [...followed, ...others] });
  } catch (error) {
    console.error("/communities error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
});

// Follow/Unfollow a community (toggle)
app.post("/communities/:id/follow", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    const communityId = req.params.id;
    let communityObjId;
    try {
      communityObjId = new ObjectId(communityId);
    } catch (_) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid community id" });
    }

    const exists = await communityFollowsCollection.findOne({
      communityId: communityObjId,
      userId: user._id,
    });

    if (exists) {
      await communityFollowsCollection.deleteOne({ _id: exists._id });
      await communityCollection.updateOne(
        { _id: communityObjId },
        { $inc: { membersCount: -1 } }
      );
      return res.json({ success: true, followed: false });
    }

    await communityFollowsCollection.insertOne({
      communityId: communityObjId,
      userId: user._id,
      createdAt: new Date(),
    });
    await communityCollection.updateOne(
      { _id: communityObjId },
      { $inc: { membersCount: 1 } }
    );
    return res.json({ success: true, followed: true });
  } catch (error) {
    console.error("/communities/:id/follow error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
});

// Follow status for a community
app.get("/communities/:id/follow-status", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.json({ success: true, followed: false });
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) return res.json({ success: true, followed: false });

    let communityObjId;
    try {
      communityObjId = new ObjectId(req.params.id);
    } catch (_) {
      return res.status(400).json({ success: false, message: "Invalid community id" });
    }

    const exists = await communityFollowsCollection.findOne({
      communityId: communityObjId,
      userId: user._id,
    });

    return res.json({ success: true, followed: !!exists });
  } catch (error) {
    console.error("/communities/:id/follow-status error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Get community detail (placed after DB collections are declared and other community routes)
app.get("/communities/:id", async (req, res) => {
  try {
    let communityObjId;
    try {
      communityObjId = new ObjectId(req.params.id);
    } catch (_) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid community id" });
    }

    const community = await communityCollection.findOne({
      _id: communityObjId,
    });
    if (!community) {
      return res
        .status(404)
        .json({ success: false, message: "Community not found" });
    }

    return res.json({ success: true, data: community });
  } catch (error) {
    console.error("/communities/:id error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
});

const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Unauthorized: Token missing" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(403).json({ message: "No User Founded" });
    }

    req.user = user; // ভবিষ্যতে রুটে ইউজার ডেটা দরকার হলে req.user থেকে নিতে পারবেন
    next();
  } catch (err) {
    console.error("Auth error:", err);
    return res.status(401).json({ message: "Unauthorized: Invalid token" });
  }
};

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
    // ✅ Fetch AI-generated result using Hugging Face Router API
    try {
      if (HUGGING_FACE_API_KEY) {
        const response = await fetch(
          "https://router.huggingface.co/v1/chat/completions",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${HUGGING_FACE_API_KEY}`,
            },
            body: JSON.stringify({
              model: "meta-llama/Llama-3.1-8B-Instruct:novita",
              messages: [
                {
                  role: "user",
                  content: `Provide a concise 2-3 sentence definition or explanation for: "${searchQuery}". Keep it brief and informative.`,
                },
              ],
              max_tokens: 150,
              temperature: 0.7,
            }),
          }
        );

        if (response.ok) {
          const data = await response.json();
          if (data?.choices?.[0]?.message?.content) {
            aiResult = data.choices[0].message.content.trim();
          }
        } else {
          console.error("HF Router API Error:", response.status, await response.text());
        }
      }
    } catch (error) {
      console.error("HF Router API Error:", error.message);
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
    console.log(userLocation);
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
    // Ensure database connection
    await connectToMongo();
    
    // Check if JWT_SECRET is set
    const jwtSecret = process.env.ACCESS_TOKEN_SECRET || JWT_SECRET;
    if (!jwtSecret) {
      console.error("JWT_SECRET is not set in environment variables");
      return res.status(500).json({
        success: false,
        message: "Server configuration error",
      });
    }

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
      jwtSecret,
      {
        expiresIn: "30d",
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
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
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
    // Ensure database connection with retry
    try {
      await connectToMongo();
    } catch (dbError) {
      console.error("Database connection error in /profile:", dbError.message);
      // Return a basic error response instead of crashing
      return res.status(503).json({ 
        error: "Service temporarily unavailable",
        message: "Database connection failed. Please try again later."
      });
    }
    
    // Check if JWT_SECRET is set
    const jwtSecret = process.env.ACCESS_TOKEN_SECRET || JWT_SECRET;
    if (!jwtSecret) {
      console.error("JWT_SECRET is not set in environment variables");
      return res.status(500).json({ error: "Server configuration error" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, jwtSecret);
    } catch (jwtError) {
      console.error("JWT Verification Error:", jwtError.message);
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    if (!decoded.number) {
      return res.status(400).json({ error: "Invalid token payload." });
    }

    const user = await usersCollections.findOne({ number: decoded.number });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json({
      id: user._id,
      name: user.name || '',
      userName: user.userName || '',
      email: user.email || '',
      number: user.number || '',
      profileImage: user.profileImage || 'https://i.ibb.co/mcL9L2t/f10ff70a7155e5ab666bcdd1b45b726d.jpg',
      verificationStatus: user.verificationStatus || false,
      work: user.work || '',
      studies: user.studies || '',
      currentCity: user.currentCity || '',
      hometown: user.hometown || '',
      coverImage: user.coverImage || 'https://i.ibb.co.com/xmyN9fT/freepik-expand-75906-min.png',
      friendRequestsSent: user.friendRequestsSent || [],
      friendRequestsReceived: user.friendRequestsReceived || [],
      friends: user.friends || [],
      role: user.role || 'user',
    });
  } catch (error) {
    console.error("Error in /profile endpoint:", error);
    res.status(500).json({ 
      error: "Internal server error",
      message: "An unexpected error occurred. Please try again later."
    });
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
    
    // Include isOnline and lastSeen in the result
    const usersWithStatus = result.map(user => ({
      ...user,
      isOnline: user.isOnline || false,
      lastSeen: user.lastSeen || null,
    }));

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
    // Ensure database connection
    try {
      await connectToMongo();
    } catch (dbError) {
      console.error("Database connection error in /all-friends:", dbError.message);
      return res.status(503).json({ 
        error: "Service temporarily unavailable",
        message: "Database connection failed. Please try again later."
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (jwtError) {
      console.error("JWT Verification Error:", jwtError.message);
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    const user = await usersCollections.findOne({ number: decoded.number });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Check if friends array exists, otherwise use empty array
    const friendsIds = user.friends || [];

    // If no friends, return empty array immediately
    if (!friendsIds.length) {
      return res.json([]);
    }

    const friends = await usersCollections
      .find({
        _id: { $in: friendsIds.map(id => new ObjectId(id)) },
      })
      .project({ password: 0 }) // Exclude password only (MongoDB doesn't allow mixing inclusion/exclusion)
      .toArray();
    
    // Add isOnline and lastSeen to each friend (these fields should already exist in the document)
    // No need to explicitly project them - they'll be included by default when we exclude password

    res.json(friends || []);
  } catch (error) {
    console.error("Error fetching friends:", error);
    // Return empty array instead of error to prevent frontend crash
    res.json([]);
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
  console.log("post token",token)
  if (!token) {
    console.log("dbcjsdcnvs.")
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

  // Validate bookId
  if (!bookId || !ObjectId.isValid(bookId)) {
    return res.status(400).json({ error: "Invalid or missing book ID." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find the current user
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    // Check if the book exists and get book details
    const book = await bookCollections.findOne({ _id: new ObjectId(bookId) });
    if (!book) {
      return res.status(404).json({ success: false, message: "Book not found." });
    }

    // Check if current user is the original owner (who added the book)
    const isOriginalOwner = book.userId?.toString() === currentUser._id.toString();

    if (!isOriginalOwner) {
      return res.status(403).json({ 
        success: false, 
        message: "Only the original owner who added this book can delete it. Transferred books cannot be deleted by the current holder." 
      });
    }

    // Only original owner can delete, proceed with deletion
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
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  // Validate bookId
  if (!bookId || !ObjectId.isValid(bookId)) {
    return res.status(400).json({ error: "Invalid or missing book ID." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find the current user
    const currentUser = await usersCollections.findOne({
      number: decoded.number,
    });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found." });
    }

    // Check if the book exists and get book details
    const book = await onindoBookCollections.findOne({ _id: new ObjectId(bookId) });
    if (!book) {
      return res.status(404).json({ success: false, message: "Book not found." });
    }

    // Check if current user is the original owner (who added the book)
    const isOriginalOwner = book.userId?.toString() === currentUser._id.toString();

    if (!isOriginalOwner) {
      return res.status(403).json({ 
        success: false, 
        message: "Only the original owner who added this book can delete it. Transferred books cannot be deleted by the current holder." 
      });
    }

    // Only original owner can delete, proceed with deletion
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

// In-memory cache for posts (5 minute TTL, 10 minute stale TTL)
const postsCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes - fresh cache
const STALE_TTL = 10 * 60 * 1000; // 10 minutes - stale but usable cache
const pendingRequests = new Map(); // Request deduplication

app.get("/all-home-books", async (req, res) => {
  try {
    const { category } = req.query;
    const cacheKey = category || "All";
    
    // Check cache first
    const cached = postsCache.get(cacheKey);
    const now = Date.now();
    
    if (cached) {
      const age = now - cached.timestamp;
      
      // Fresh cache - return immediately
      if (age < CACHE_TTL) {
        res.set('Content-Type', 'application/json');
        res.set('X-Cache', 'HIT');
        return res.json(cached.data);
      }
      
      // Stale cache - return it but refresh in background (stale-while-revalidate)
      if (age < STALE_TTL) {
        res.set('Content-Type', 'application/json');
        res.set('X-Cache', 'STALE');
        
        // Trigger background refresh if not already in progress
        if (!pendingRequests.has(cacheKey)) {
          refreshCacheInBackground(cacheKey, category).catch(err => {
            console.error("Background cache refresh failed:", err);
          });
        }
        
        return res.json(cached.data);
      }
    }
    
    // Check if request is already in progress (deduplication)
    if (pendingRequests.has(cacheKey)) {
      // Wait for the pending request to complete
      try {
        const result = await pendingRequests.get(cacheKey);
        res.set('Content-Type', 'application/json');
        res.set('X-Cache', 'DEDUPED');
        return res.json(result);
      } catch (error) {
        // If pending request failed, try to get stale cache or proceed with new request
        if (cached && (now - cached.timestamp < STALE_TTL)) {
          res.set('Content-Type', 'application/json');
          res.set('X-Cache', 'STALE-FALLBACK');
          return res.json(cached.data);
        }
        // Continue to new request
      }
    }
    
    // Create new request promise
    const requestPromise = fetchPostsFromDatabase(category, cacheKey);
    pendingRequests.set(cacheKey, requestPromise);
    
    try {
      const mappedPosts = await requestPromise;
      
      // Cache the result
      postsCache.set(cacheKey, {
        data: mappedPosts,
        timestamp: Date.now()
      });
      
      // Send response immediately
      res.set('Content-Type', 'application/json');
      res.set('X-Cache', 'MISS');
      res.json(mappedPosts || []);
    } finally {
      // Remove from pending requests
      pendingRequests.delete(cacheKey);
    }
    
  } catch (error) {
    console.error("Error fetching posts:", error);
    
    const { category } = req.query;
    const cacheKey = category || "All";
    const cached = postsCache.get(cacheKey);
    const now = Date.now();
    
    // Try to return stale cache as fallback (even if very old, better than error)
    if (cached && cached.data && Array.isArray(cached.data)) {
      console.warn("Database error - returning cached data as fallback");
      res.set('Content-Type', 'application/json');
      res.set('X-Cache', 'STALE-FALLBACK');
      return res.json(cached.data);
    }
    
    // If no cache available, return empty array instead of error
    // This prevents frontend crashes during presentation
    console.warn("No cache available - returning empty array");
    res.set('Content-Type', 'application/json');
    res.set('X-Cache', 'MISS-FALLBACK');
    return res.json([]);
  }
});

// Helper function to fetch posts from database
async function fetchPostsFromDatabase(category, cacheKey) {
  try {
    // Ensure database connection
    await connectToMongo();
  } catch (dbError) {
    console.error("Database connection failed in fetchPostsFromDatabase:", dbError.message);
    // Check if we have stale cache to return (even if very old)
    const cached = postsCache.get(cacheKey);
    if (cached && cached.data && Array.isArray(cached.data)) {
      console.warn("Returning cached data due to database connection failure");
      return cached.data;
    }
    // If no cache, return empty array instead of throwing error
    console.warn("No cache available - returning empty array");
    return [];
  }
  
  // Verify collections are accessible
  if (!adminPostCollections) {
    // Try to return stale cache if available
    const cached = postsCache.get(cacheKey);
    if (cached && cached.data && Array.isArray(cached.data)) {
      console.warn("Collections not initialized - returning cached data");
      return cached.data;
    }
    // If no cache, return empty array instead of throwing error
    console.warn("Collections not initialized - returning empty array");
    return [];
  }
  
  try {
    let query = {};

    if (category && category !== "All") {
      query.category = category;
    }

    // Optimized query with limit, sort, and projection
    const posts = await adminPostCollections
      .find(query, {
        projection: {
          _id: 1,
          postText: 1,
          message: 1,
          content: 1,
          text: 1,
          postImage: 1,
          image: 1,
          imageUrl: 1,
          photo: 1,
          title: 1,
          heading: 1,
          category: 1,
          date: 1,
          time: 1,
          userName: 1,
          userImage: 1,
          likes: 1,
          likedBy: 1,
          createdAt: 1,
        }
      })
      .sort({ createdAt: -1 })
      .limit(50)
      .maxTimeMS(8000)
      .toArray();
    
    // Map backend field names to frontend expected field names
    return posts.map((post) => {
      const textContent = post.postText || post.message || post.content || post.text || '';
      const imageUrl = post.postImage || post.image || post.imageUrl || post.photo || '';
      const postTitle = post.title || post.heading || 'Untitled';
      
      return {
        _id: post._id,
        message: textContent,
        image: imageUrl,
        title: postTitle,
        postText: textContent,
        postImage: imageUrl,
        category: post.category,
        date: post.date,
        time: post.time,
        userName: post.userName,
        userImage: post.userImage,
        likes: post.likes || 0,
        likedBy: post.likedBy || [],
        createdAt: post.createdAt,
      };
    });
  } catch (queryError) {
    console.error("Database query error in fetchPostsFromDatabase:", queryError.message);
    // Try to return stale cache if available (even if very old)
    const cached = postsCache.get(cacheKey);
    if (cached && cached.data && Array.isArray(cached.data)) {
      console.warn("Query failed - returning cached data");
      return cached.data;
    }
    // If no cache, return empty array instead of throwing error
    console.warn("No cache available - returning empty array");
    return [];
  }
}

// Background cache refresh (stale-while-revalidate)
async function refreshCacheInBackground(cacheKey, category) {
  try {
    const mappedPosts = await fetchPostsFromDatabase(category, cacheKey);
    postsCache.set(cacheKey, {
      data: mappedPosts,
      timestamp: Date.now()
    });
    console.log(`✅ Background cache refreshed for: ${cacheKey}`);
  } catch (error) {
    console.error(`❌ Background cache refresh failed for ${cacheKey}:`, error.message);
    // Don't throw - this is background refresh, failure is acceptable
  }
}

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
      .project({ name: 1, profileImage: 1, isOnline: 1, lastSeen: 1 })
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
            lastMessageTime: lastMessage[0]?.timestamp || null,
            sender: lastMessage[0]
              ? lastMessage[0].senderId.toString() === user._id.toString()
                ? "You"
                : chatUser.name
              : null,
            isOnline: chatUser.isOnline || false,
            lastSeen: chatUser.lastSeen || null,
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

// Get all notifications for a user
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
    // Fetch notifications for the user
    const notifications = await notifyCollections
      .find({ receoientId: new ObjectId(userId) })
      .sort({ timestamp: -1 })
      .toArray();

    res.json({ success: true, notifications });
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

// Get unread notification count
app.get("/api/notifications/:userId/unread-count", async (req, res) => {
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
    // Count unread notifications
    const unreadCount = await notifyCollections.countDocuments({
      receoientId: new ObjectId(userId),
      isRead: false,
    });

    res.json({ success: true, unreadCount });
  } catch (error) {
    console.error("Error fetching unread count:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

// Mark notifications as read
app.put("/api/notifications/mark-read", async (req, res) => {
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

    const { userId, notificationIds } = req.body;

    if (notificationIds && notificationIds.length > 0) {
      // Mark specific notifications as read
      await notifyCollections.updateMany(
        {
          _id: { $in: notificationIds.map(id => new ObjectId(id)) },
          receoientId: new ObjectId(userId),
        },
        { $set: { isRead: true, readAt: new Date() } }
      );
    } else {
      // Mark all notifications as read for the user
      await notifyCollections.updateMany(
        { receoientId: new ObjectId(userId), isRead: false },
        { $set: { isRead: true, readAt: new Date() } }
      );
    }

    res.json({ success: true, message: "Notifications marked as read" });
  } catch (error) {
    console.error("Error marking notifications as read:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

// Get unread message count
app.get("/api/messages/:userId/unread-count", async (req, res) => {
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
    // Count unread messages
    const unreadCount = await messagesCollections.countDocuments({
      receoientId: new ObjectId(userId),
      isRead: false,
    });

    res.json({ success: true, unreadCount });
  } catch (error) {
    console.error("Error fetching unread message count:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

// Mark messages as read
app.put("/api/messages/mark-read", async (req, res) => {
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

    const { userId, senderId } = req.body;

    // Mark all messages from a specific sender as read
    await messagesCollections.updateMany(
      {
        receoientId: new ObjectId(userId),
        senderId: new ObjectId(senderId),
        isRead: false,
      },
      { $set: { isRead: true, readAt: new Date() } }
    );

    res.json({ success: true, message: "Messages marked as read" });
  } catch (error) {
    console.error("Error marking messages as read:", error);
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

// Simple endpoint - no cache, direct database query
app.get("/home-category", async (req, res) => {
  try {
    // Ensure database connection
    await connectToMongo();
    
    // Verify collections are accessible
    if (!homeCategoryCollection) {
      return res.json({ success: true, categories: [] });
    }
    
    const categories = await homeCategoryCollection
      .find()
      .limit(50)
      .maxTimeMS(10000)
      .toArray();
    
    res.json({ success: true, categories: categories || [] });
  } catch (error) {
    console.error("Error while getting category:", error);
    res.json({ success: true, categories: [] }); // Return empty array on error
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

    const requests = await sellerCollections
      .find()
      .sort({ createdAt: -1 })
      .toArray();
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
    const products = await productsCollection
      .find()
      .sort({ createdAt: -1 })
      .toArray();

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
    const orders = await ordersCollection
      .find()
      .sort({ createdAt: -1 })
      .toArray();
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
            _id: "$category", // category অনুযায়ী group
            count: { $sum: 1 }, // প্রতিটা category এর product সংখ্যা
          },
        },
        { $sort: { count: -1 } }, // বেশি product আগে
        { $limit: 1 }, // শুধু ১টা category আনবে
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
    const products = await productsCollection
      .find({ isFeatured: true })
      .toArray();
    res.json({ success: true, products });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// =====================
// Jobs and Employment APIs
// =====================

// Employer: apply for posting permission
app.post("/employers/apply", verifyTokenEarly, async (req, res) => {
  try {
    const { companyName, companyWebsite, companyLocation, description } = req.body || {};
    if (!companyName) {
      return res.status(400).json({ success: false, message: "companyName is required" });
    }
    const existing = await employersCollection.findOne({ userId: req.user._id });
    if (existing) {
      return res.status(200).json({ success: true, message: "Application already submitted", data: existing });
    }
    const doc = {
      userId: req.user._id,
      companyName,
      companyWebsite: companyWebsite || "",
      companyLocation: companyLocation || "",
      description: description || "",
      approved: false,
      status: "pending",
      createdAt: new Date(),
    };
    const result = await employersCollection.insertOne(doc);
    return res.json({ success: true, data: { _id: result.insertedId, ...doc } });
  } catch (e) {
    console.error("POST /employers/apply", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Employer: status
app.get("/employers/status", verifyTokenEarly, async (req, res) => {
  try {
    const employer = await employersCollection.findOne({ userId: req.user._id });
    return res.json({ success: true, approved: !!employer?.approved, status: employer?.status || "none", employer });
  } catch (e) {
    console.error("GET /employers/status", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Admin: list employer requests (reuse role field if available; here simple guard by role === 'admin')
app.get("/admin/employers/requests", verifyTokenEarly, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, message: "Forbidden" });
    const items = await employersCollection.find({ status: "pending" }).sort({ createdAt: -1 }).toArray();
    return res.json({ success: true, data: items });
  } catch (e) {
    console.error("GET /admin/employers/requests", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.patch("/admin/employers/:id/approve", verifyTokenEarly, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, message: "Forbidden" });
    const { id } = req.params;
    const result = await employersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { approved: true, status: "approved", approvedAt: new Date(), approvedBy: req.user._id } }
    );
    if (!result.matchedCount) return res.status(404).json({ success: false, message: "Request not found" });
    return res.json({ success: true });
  } catch (e) {
    console.error("PATCH /admin/employers/:id/approve", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.patch("/admin/employers/:id/reject", verifyTokenEarly, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, message: "Forbidden" });
    const { id } = req.params;
    const { reason } = req.body || {};
    const result = await employersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { approved: false, status: "rejected", rejectedAt: new Date(), rejectedBy: req.user._id, reason: reason || "" } }
    );
    if (!result.matchedCount) return res.status(404).json({ success: false, message: "Request not found" });
    return res.json({ success: true });
  } catch (e) {
    console.error("PATCH /admin/employers/:id/reject", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Helper: ensure employer approved
async function ensureEmployerApproved(userId) {
  const emp = await employersCollection.findOne({ userId: new ObjectId(userId) });
  return !!emp?.approved;
}

// Create a job (employer only)
app.post("/jobs", verifyTokenEarly, async (req, res) => {
  try {
    const isApproved = await employersCollection.findOne({ userId: req.user._id, approved: true });
    if (!isApproved) return res.status(403).json({ success: false, message: "Employer approval required" });
    const {
      title, description, category, location, jobType, experienceLevel,
      salaryMin, salaryMax, skills, deadline
    } = req.body || {};
    if (!title || !description) {
      return res.status(400).json({ success: false, message: "title and description are required" });
    }
    const job = {
      title,
      description,
      category: category || "",
      location: location || "",
      jobType: jobType || "Full-time",
      experienceLevel: experienceLevel || "Any",
      salaryMin: salaryMin ? Number(salaryMin) : null,
      salaryMax: salaryMax ? Number(salaryMax) : null,
      skills: Array.isArray(skills) ? skills : [],
      deadline: deadline ? new Date(deadline) : null,
      postedBy: req.user._id,
      status: "open",
      createdAt: new Date(),
      updatedAt: new Date(),
      views: 0,
      applicationsCount: 0,
    };
    const result = await jobsCollection.insertOne(job);
    return res.json({ success: true, data: { _id: result.insertedId, ...job } });
  } catch (e) {
    console.error("POST /jobs", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// List jobs with filters and pagination
app.get("/jobs", async (req, res) => {
  try {
    const { q, category, location, jobType, experienceLevel, minSalary, maxSalary, page = 1, limit = 10 } = req.query || {};
    const query = { status: "open" };
    if (q) query.title = { $regex: q, $options: "i" };
    if (category) query.category = category;
    if (location) query.location = { $regex: location, $options: "i" };
    if (jobType) query.jobType = jobType;
    if (experienceLevel) query.experienceLevel = experienceLevel;
    if (minSalary) query.salaryMin = { $gte: Number(minSalary) };
    if (maxSalary) query.salaryMax = { ...(query.salaryMax || {}), $lte: Number(maxSalary) };
    const skip = (Number(page) - 1) * Number(limit);
    const cursor = jobsCollection.find(query).sort({ createdAt: -1 }).skip(skip).limit(Number(limit));
    const [items, total] = await Promise.all([cursor.toArray(), jobsCollection.countDocuments(query)]);
    return res.json({ success: true, data: items, pagination: { page: Number(page), limit: Number(limit), total } });
  } catch (e) {
    console.error("GET /jobs", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Job detail
app.get("/jobs/:id", async (req, res) => {
  try {
    const { id } = req.params;
    let objId;
    try { objId = new ObjectId(id); } catch { return res.status(400).json({ success: false, message: "Invalid id" }); }
    const job = await jobsCollection.findOne({ _id: objId });
    if (!job) return res.status(404).json({ success: false, message: "Job not found" });
    await jobsCollection.updateOne({ _id: objId }, { $inc: { views: 1 } });
    return res.json({ success: true, data: job });
  } catch (e) {
    console.error("GET /jobs/:id", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Update/close job (employer)
app.patch("/jobs/:id", verifyTokenEarly, async (req, res) => {
  try {
    const { id } = req.params;
    let objId;
    try { objId = new ObjectId(id); } catch { return res.status(400).json({ success: false, message: "Invalid id" }); }
    const job = await jobsCollection.findOne({ _id: objId });
    if (!job) return res.status(404).json({ success: false, message: "Job not found" });
    if (job.postedBy.toString() !== req.user._id.toString()) return res.status(403).json({ success: false, message: "Forbidden" });
    const allowed = ["title", "description", "category", "location", "jobType", "experienceLevel", "salaryMin", "salaryMax", "skills", "deadline", "status"];
    const $set = { updatedAt: new Date() };
    for (const key of allowed) {
      if (key in req.body) $set[key] = key.includes("salary") ? Number(req.body[key]) : req.body[key];
    }
    await jobsCollection.updateOne({ _id: objId }, { $set });
    return res.json({ success: true });
  } catch (e) {
    console.error("PATCH /jobs/:id", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Apply to job
app.post("/jobs/:id/apply", verifyTokenEarly, async (req, res) => {
  try {
    const { id } = req.params;
    let objId;
    try { objId = new ObjectId(id); } catch { return res.status(400).json({ success: false, message: "Invalid id" }); }
    const job = await jobsCollection.findOne({ _id: objId });
    if (!job || job.status !== "open") return res.status(404).json({ success: false, message: "Job not open" });
    const { cvUrl, coverLetter } = req.body || {};
    const exists = await jobApplicationsCollection.findOne({ jobId: objId, userId: req.user._id });
    if (exists) return res.status(200).json({ success: true, message: "Already applied" });
    const appDoc = {
      jobId: objId,
      userId: req.user._id,
      cvUrl: cvUrl || "",
      coverLetter: coverLetter || "",
      status: "applied",
      createdAt: new Date(),
    };
    await jobApplicationsCollection.insertOne(appDoc);
    await jobsCollection.updateOne({ _id: objId }, { $inc: { applicationsCount: 1 } });
    return res.json({ success: true });
  } catch (e) {
    console.error("POST /jobs/:id/apply", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Applicant: my applications
app.get("/my-applications", verifyTokenEarly, async (req, res) => {
  try {
    const apps = await jobApplicationsCollection
      .aggregate([
        { $match: { userId: req.user._id } },
        { $lookup: { from: "jobsCollection", localField: "jobId", foreignField: "_id", as: "job" } },
        { $unwind: "$job" },
        { $sort: { createdAt: -1 } },
      ])
      .toArray();
    return res.json({ success: true, data: apps });
  } catch (e) {
    console.error("GET /my-applications", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Employer: my jobs
app.get("/employer/jobs", verifyTokenEarly, async (req, res) => {
  try {
    const isApproved = await employersCollection.findOne({ userId: req.user._id, approved: true });
    if (!isApproved) return res.status(403).json({ success: false, message: "Employer approval required" });
    const items = await jobsCollection.find({ postedBy: req.user._id }).sort({ createdAt: -1 }).toArray();
    return res.json({ success: true, data: items });
  } catch (e) {
    console.error("GET /employer/jobs", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Employer: applications for a job
app.get("/employer/jobs/:id/applications", verifyTokenEarly, async (req, res) => {
  try {
    const { id } = req.params;
    let objId;
    try { objId = new ObjectId(id); } catch { return res.status(400).json({ success: false, message: "Invalid id" }); }
    const job = await jobsCollection.findOne({ _id: objId });
    if (!job) return res.status(404).json({ success: false, message: "Job not found" });
    if (job.postedBy.toString() !== req.user._id.toString()) return res.status(403).json({ success: false, message: "Forbidden" });
    const apps = await jobApplicationsCollection
      .aggregate([
        { $match: { jobId: objId } },
        { $lookup: { from: "usersCollections", localField: "userId", foreignField: "_id", as: "applicant" } },
        { $unwind: "$applicant" },
        { $sort: { createdAt: -1 } },
      ])
      .toArray();
    return res.json({ success: true, data: apps });
  } catch (e) {
    console.error("GET /employer/jobs/:id/applications", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// =====================
// Freelance Marketplace APIs
// =====================

// Client: Post a project
app.post("/projects", verifyTokenEarly, async (req, res) => {
  try {
    const { title, description, category, budgetType, budget, skills, deadline } = req.body;
    if (!title || !description || !category || !budgetType) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }
    const project = {
      title,
      description,
      category,
      budgetType, // 'fixed' or 'hourly'
      budget: budgetType === 'fixed' ? Number(budget) : null,
      hourlyRate: budgetType === 'hourly' ? Number(budget) : null,
      skills: Array.isArray(skills) ? skills : [],
      deadline: deadline ? new Date(deadline) : null,
      postedBy: req.user._id,
      status: 'open', // 'open', 'in_progress', 'completed', 'cancelled'
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const result = await projectsCollection.insertOne(project);
    return res.json({ success: true, data: { _id: result.insertedId, ...project } });
  } catch (e) {
    console.error("POST /projects", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Get all projects with filters and pagination
app.get("/projects", async (req, res) => {
  try {
    const { q, category, budgetType, budgetMin, budgetMax, page = 1, limit = 10 } = req.query;
    const pageNum = Number(page);
    const limitNum = Number(limit);
    const skip = (pageNum - 1) * limitNum;

    const query = { status: 'open' };
    if (q) {
      query.$or = [
        { title: { $regex: q, $options: 'i' } },
        { description: { $regex: q, $options: 'i' } },
      ];
    }
    if (category) query.category = category;
    if (budgetType) query.budgetType = budgetType;
    if (budgetMin) {
      if (budgetType === 'fixed') {
        query.budget = { ...query.budget, $gte: Number(budgetMin) };
      } else {
        query.hourlyRate = { ...query.hourlyRate, $gte: Number(budgetMin) };
      }
    }
    if (budgetMax) {
      if (budgetType === 'fixed') {
        query.budget = { ...query.budget, $lte: Number(budgetMax) };
      } else {
        query.hourlyRate = { ...query.hourlyRate, $lte: Number(budgetMax) };
      }
    }

    const [projects, total] = await Promise.all([
      projectsCollection.find(query).sort({ createdAt: -1 }).skip(skip).limit(limitNum).toArray(),
      projectsCollection.countDocuments(query),
    ]);

    // Populate postedBy user info
    const userIds = [...new Set(projects.map(p => p.postedBy.toString()))];
    const users = await usersCollections.find({ _id: { $in: userIds.map(id => new ObjectId(id)) } })
      .project({ _id: 1, name: 1, profileImage: 1 })
      .toArray();
    const userMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));

    const projectsWithUser = projects.map(p => ({
      ...p,
      postedByUser: userMap[p.postedBy.toString()] || null,
    }));

    return res.json({
      success: true,
      data: projectsWithUser,
      pagination: { page: pageNum, limit: limitNum, total, totalPages: Math.ceil(total / limitNum) },
    });
  } catch (e) {
    console.error("GET /projects", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Get single project
app.get("/projects/:id", async (req, res) => {
  try {
    const { id } = req.params;
    let objId;
    try { objId = new ObjectId(id); } catch { return res.status(400).json({ success: false, message: "Invalid id" }); }
    const project = await projectsCollection.findOne({ _id: objId });
    if (!project) return res.status(404).json({ success: false, message: "Project not found" });

    // Populate postedBy user
    const user = await usersCollections.findOne({ _id: project.postedBy }, { projection: { _id: 1, name: 1, profileImage: 1, email: 1 } });
    
    // Populate selectedFreelancer if exists
    let selectedFreelancerUser = null;
    if (project.selectedFreelancer) {
      selectedFreelancerUser = await usersCollections.findOne(
        { _id: project.selectedFreelancer },
        { projection: { _id: 1, name: 1, profileImage: 1, email: 1 } }
      );
    }
    
    return res.json({
      success: true,
      data: {
        ...project,
        postedByUser: user || null,
        selectedFreelancerUser: selectedFreelancerUser || null,
      },
    });
  } catch (e) {
    console.error("GET /projects/:id", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Freelancer: Submit proposal
app.post("/projects/:id/proposals", verifyTokenEarly, async (req, res) => {
  try {
    const { id } = req.params;
    let objId;
    try { objId = new ObjectId(id); } catch { return res.status(400).json({ success: false, message: "Invalid id" }); }
    const project = await projectsCollection.findOne({ _id: objId });
    if (!project) return res.status(404).json({ success: false, message: "Project not found" });
    if (project.status !== 'open') return res.status(400).json({ success: false, message: "Project is not open for proposals" });
    if (project.postedBy.toString() === req.user._id.toString()) {
      return res.status(400).json({ success: false, message: "You cannot propose to your own project" });
    }

    const { coverLetter, proposedPrice, deliveryTime, hourlyRate } = req.body;
    if (!coverLetter || (!proposedPrice && !hourlyRate)) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    // Check if already proposed
    const exists = await proposalsCollection.findOne({ projectId: objId, freelancerId: req.user._id });
    if (exists) return res.status(400).json({ success: false, message: "You have already submitted a proposal" });

    const proposal = {
      projectId: objId,
      freelancerId: req.user._id,
      coverLetter,
      proposedPrice: project.budgetType === 'fixed' ? Number(proposedPrice) : null,
      hourlyRate: project.budgetType === 'hourly' ? Number(hourlyRate) : null,
      deliveryTime, // e.g., "3 days", "1 week"
      status: 'pending', // 'pending', 'accepted', 'rejected'
      createdAt: new Date(),
    };
    const result = await proposalsCollection.insertOne(proposal);
    return res.json({ success: true, data: { _id: result.insertedId, ...proposal } });
  } catch (e) {
    console.error("POST /projects/:id/proposals", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Get proposals for a project (client only)
app.get("/projects/:id/proposals", verifyTokenEarly, async (req, res) => {
  try {
    const { id } = req.params;
    let objId;
    try { objId = new ObjectId(id); } catch { return res.status(400).json({ success: false, message: "Invalid id" }); }
    const project = await projectsCollection.findOne({ _id: objId });
    if (!project) return res.status(404).json({ success: false, message: "Project not found" });
    if (project.postedBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, message: "Forbidden" });
    }

    const proposals = await proposalsCollection
      .aggregate([
        { $match: { projectId: objId } },
        { $lookup: { from: "usersCollections", localField: "freelancerId", foreignField: "_id", as: "freelancer" } },
        { $unwind: "$freelancer" },
        { $sort: { createdAt: -1 } },
      ])
      .toArray();
    return res.json({ success: true, data: proposals });
  } catch (e) {
    console.error("GET /projects/:id/proposals", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Client: Accept/Reject proposal
app.patch("/proposals/:id/status", verifyTokenEarly, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body; // 'accepted' or 'rejected'
    if (!['accepted', 'rejected'].includes(status)) {
      return res.status(400).json({ success: false, message: "Invalid status" });
    }
    let objId;
    try { objId = new ObjectId(id); } catch { return res.status(400).json({ success: false, message: "Invalid id" }); }

    const proposal = await proposalsCollection.findOne({ _id: objId });
    if (!proposal) return res.status(404).json({ success: false, message: "Proposal not found" });

    const project = await projectsCollection.findOne({ _id: proposal.projectId });
    if (!project) return res.status(404).json({ success: false, message: "Project not found" });
    if (project.postedBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, message: "Forbidden" });
    }

    await proposalsCollection.updateOne({ _id: objId }, { $set: { status, updatedAt: new Date() } });

    if (status === 'accepted') {
      // Update project status and reject other proposals
      await projectsCollection.updateOne({ _id: proposal.projectId }, { $set: { status: 'in_progress', selectedFreelancer: proposal.freelancerId, updatedAt: new Date() } });
      await proposalsCollection.updateMany(
        { projectId: proposal.projectId, _id: { $ne: objId } },
        { $set: { status: 'rejected', updatedAt: new Date() } }
      );
    }

    return res.json({ success: true });
  } catch (e) {
    console.error("PATCH /proposals/:id/status", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Client: Get my projects
app.get("/client/projects", verifyTokenEarly, async (req, res) => {
  try {
    const projects = await projectsCollection
      .find({ postedBy: req.user._id })
      .sort({ createdAt: -1 })
      .toArray();
    return res.json({ success: true, data: projects });
  } catch (e) {
    console.error("GET /client/projects", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Freelancer: Get my proposals
app.get("/freelancer/proposals", verifyTokenEarly, async (req, res) => {
  try {
    const proposals = await proposalsCollection
      .aggregate([
        { $match: { freelancerId: req.user._id } },
        { $lookup: { from: "projectsCollection", localField: "projectId", foreignField: "_id", as: "project" } },
        { $unwind: "$project" },
        { $sort: { createdAt: -1 } },
      ])
      .toArray();
    return res.json({ success: true, data: proposals });
  } catch (e) {
    console.error("GET /freelancer/proposals", e);
    return res.status(500).json({ success: false, message: "Internal server error" });
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
                    {
                      $divide: [
                        { $subtract: ["$price", "$discountPrice"] },
                        "$price",
                      ],
                    },
                    100,
                  ],
                },
                0,
              ],
            },
          },
        },
        { $sort: { discountPercent: -1 } },
        { $limit: 5 },
      ])
      .toArray();

    res.json({ success: true, products });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Upload video to Cloudinary
app.post("/upload/video", videoUpload.single("video"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: "No video file uploaded" });
    }

    // Cloudinary automatically uploads and returns the URL
    const videoUrl = req.file.path;
    const publicId = req.file.filename;

    return res.status(200).json({
      success: true,
      message: "Video uploaded successfully",
      videoUrl,
      publicId,
      duration: req.file.duration || null,
      format: req.file.format || null,
    });
  } catch (error) {
    console.error("POST /upload/video error:", error);
    return res.status(500).json({ success: false, message: "Failed to upload video" });
  }
});

// Delete video from Cloudinary (optional)
app.delete("/upload/video/:publicId", async (req, res) => {
  try {
    const { publicId } = req.params;
    const decodedPublicId = decodeURIComponent(publicId);

    await cloudinary.uploader.destroy(decodedPublicId, { resource_type: "video" });

    return res.status(200).json({
      success: true,
      message: "Video deleted successfully",
    });
  } catch (error) {
    console.error("DELETE /upload/video/:publicId error:", error);
    return res.status(500).json({ success: false, message: "Failed to delete video" });
  }
});

// Initialize database connection on startup
(async () => {
  try {
    console.log("🔄 Attempting initial MongoDB connection...");
    await connectToMongo();
    
    // Verify we can access collections
    const db = client.db("flybook");
    const testCollection = db.collection("usersCollections");
    await testCollection.findOne({}, { limit: 1 }).catch(() => {
      // Collection might be empty, which is okay
    });
    
    console.log("✅ Database connection established on startup");
    console.log("✅ Database collections are accessible");
  } catch (error) {
    console.error("❌ Failed to connect to database on startup:", error.message);
    console.error("⚠️  Server will start but database operations may fail");
    console.error("⚠️  Please check:");
    console.error("   1. MongoDB Atlas cluster is running");
    console.error("   2. DB_USER and DB_PASS environment variables are set correctly");
    console.error("   3. IP address is whitelisted in MongoDB Atlas");
    console.error("   4. Network connectivity to MongoDB Atlas");
  }
})();

const server = app.listen(port, () => {
  console.log(`Server running http://localhost:${port}`);
});

const io = new Server(server, {
  cors: {
    origin: ["https://flybook.com.bd", "https://flybook-f23c5.web.app", "http://localhost:5173"],
    methods: ["GET", "POST"],
    credentials: true,
  },
  transports: ["websocket", "polling"], // Enable both transports
  allowEIO3: true, // Enable compatibility with older clients
});

io.on("connection", (socket) => {
  // ইউজারকে রুমে যোগ করা
  socket.on("joinRoom", (userId) => {
    const roomId = [userId].sort().join("-");
    socket.join(roomId);
    console.log("user join", roomId);
    socket.emit("connected");
  });

  socket.on("joinUser", async (userId) => {
    const roomId = userId;
    socket.join(roomId); // ইউজারকে রুমে যোগ করা
    socket.userId = userId; // Store userId in socket for disconnect handling
    
    try {
      // Mark user as online in database
      await usersCollections.updateOne(
        { _id: new ObjectId(userId) },
        { 
          $set: { 
            isOnline: true,
            lastSeen: new Date()
          } 
        }
      );
      
      // Broadcast user online status to all connected clients
      io.emit("userOnline", { userId });
      
      console.log("user joined and marked online:", roomId);
    } catch (error) {
      console.error("Error marking user online:", error);
    }
    
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
        isRead: false, // Unread by default
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
        isRead: false, // Unread by default
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

  socket.on("disconnect", async () => {
    console.log("A user disconnected:", socket.id);
    
    // Mark user as offline if userId is stored
    if (socket.userId) {
      try {
        await usersCollections.updateOne(
          { _id: new ObjectId(socket.userId) },
          { 
            $set: { 
              isOnline: false,
              lastSeen: new Date()
            } 
          }
        );
        
        // Broadcast user offline status to all connected clients
        io.emit("userOffline", { userId: socket.userId });
        
        console.log("user marked offline:", socket.userId);
      } catch (error) {
        console.error("Error marking user offline:", error);
      }
    }
  });
});

// =====================
// ADMIN COMMUNITY MANAGEMENT ENDPOINTS
// =====================

// Get all communities with stats (admin only)
app.get("/admin/communities", verifyToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Admin access required" });
    }

    const communities = await communityCollection.find({}).sort({ createdAt: -1 }).toArray();
    
    // Enrich with stats
    const enriched = await Promise.all(
      communities.map(async (comm) => {
        const postsCount = await communityPostsCollection.countDocuments({ communityId: comm._id });
        const coursesCount = await communityCoursesCollection.countDocuments({ communityId: comm._id });
        const followsCount = await communityFollowsCollection.countDocuments({ communityId: comm._id });
        
        // Get owner info
        const owner = await usersCollections.findOne(
          { _id: comm.mainAdmin },
          { projection: { name: 1, number: 1, email: 1 } }
        );

        return {
          ...comm,
          postsCount,
          coursesCount,
          membersCount: followsCount,
          owner
        };
      })
    );

    return res.json({ success: true, data: enriched });
  } catch (error) {
    console.error("GET /admin/communities error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Get community details with all posts and courses (admin only)
app.get("/admin/communities/:id/details", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Admin access required" });
    }

    let communityObjId;
    try {
      communityObjId = new ObjectId(req.params.id);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid community id" });
    }

    const community = await communityCollection.findOne({ _id: communityObjId });
    if (!community) {
      return res.status(404).json({ success: false, message: "Community not found" });
    }

    // Get all posts
    const posts = await communityPostsCollection.find({ communityId: communityObjId }).sort({ createdAt: -1 }).toArray();
    
    // Enrich posts with author info and stats
    const enrichedPosts = await Promise.all(
      posts.map(async (post) => {
        const author = await usersCollections.findOne(
          { _id: post.authorId },
          { projection: { name: 1, number: 1, image: 1 } }
        );
        
        const likesCount = await communityPostLikesCollection.countDocuments({ postId: post._id });
        
        let courseInfo = null;
        if (post.type === "course") {
          const course = await communityCoursesCollection.findOne({ postId: post._id });
          if (course) {
            const enrollmentsCount = await communityEnrollmentsCollection.countDocuments({ courseId: course._id });
            const chaptersCount = await communityChaptersCollection.countDocuments({ courseId: course._id });
            const lessonsCount = await communityLessonsCollection.countDocuments({ courseId: course._id });
            
            courseInfo = {
              courseId: course._id,
              enrollmentsCount,
              chaptersCount,
              lessonsCount
            };
          }
        }

        return {
          ...post,
          author,
          likesCount,
          courseInfo
        };
      })
    );

    // Get members
    const follows = await communityFollowsCollection.find({ communityId: communityObjId }).toArray();
    const memberIds = follows.map(f => f.userId);
    const members = await usersCollections.find(
      { _id: { $in: memberIds } },
      { projection: { name: 1, number: 1, image: 1, email: 1 } }
    ).toArray();

    return res.json({
      success: true,
      data: {
        community,
        posts: enrichedPosts,
        members
      }
    });
  } catch (error) {
    console.error("GET /admin/communities/:id/details error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Delete community (admin only) - cascade delete all related data
app.delete("/admin/communities/:id", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Admin access required" });
    }

    let communityObjId;
    try {
      communityObjId = new ObjectId(req.params.id);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid community id" });
    }

    const community = await communityCollection.findOne({ _id: communityObjId });
    if (!community) {
      return res.status(404).json({ success: false, message: "Community not found" });
    }

    // Get all posts
    const posts = await communityPostsCollection.find({ communityId: communityObjId }).toArray();
    const postIds = posts.map(p => p._id);

    // Get all courses
    const courses = await communityCoursesCollection.find({ communityId: communityObjId }).toArray();
    const courseIds = courses.map(c => c._id);

    // Cascade delete everything
    await Promise.all([
      // Delete posts and likes
      communityPostsCollection.deleteMany({ communityId: communityObjId }),
      communityPostLikesCollection.deleteMany({ postId: { $in: postIds } }),
      
      // Delete courses and related data
      communityCoursesCollection.deleteMany({ communityId: communityObjId }),
      communityChaptersCollection.deleteMany({ courseId: { $in: courseIds } }),
      communityLessonsCollection.deleteMany({ courseId: { $in: courseIds } }),
      communityExamsCollection.deleteMany({ courseId: { $in: courseIds } }),
      communityExamAttemptsCollection.deleteMany({ courseId: { $in: courseIds } }),
      communityEnrollmentsCollection.deleteMany({ courseId: { $in: courseIds } }),
      communityProgressCollection.deleteMany({ courseId: { $in: courseIds } }),
      communityCertificatesCollection.deleteMany({ courseId: { $in: courseIds } }),
      
      // Delete follows
      communityFollowsCollection.deleteMany({ communityId: communityObjId }),
      
      // Finally delete community
      communityCollection.deleteOne({ _id: communityObjId })
    ]);

    return res.json({ success: true, message: "Community and all related data deleted" });
  } catch (error) {
    console.error("DELETE /admin/communities/:id error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Toggle community verification (admin only)
app.patch("/admin/communities/:id/verify", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Admin access required" });
    }

    let communityObjId;
    try {
      communityObjId = new ObjectId(req.params.id);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid community id" });
    }

    const community = await communityCollection.findOne({ _id: communityObjId });
    if (!community) {
      return res.status(404).json({ success: false, message: "Community not found" });
    }

    const newVerifiedStatus = !community.isVerified;
    await communityCollection.updateOne(
      { _id: communityObjId },
      { $set: { isVerified: newVerifiedStatus, updatedAt: new Date() } }
    );

    return res.json({ success: true, isVerified: newVerifiedStatus });
  } catch (error) {
    console.error("PATCH /admin/communities/:id/verify error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Delete post (admin override)
app.delete("/admin/posts/:postId", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Admin access required" });
    }

    let postObjId;
    try {
      postObjId = new ObjectId(req.params.postId);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid post id" });
    }

    const post = await communityPostsCollection.findOne({ _id: postObjId });
    if (!post) {
      return res.status(404).json({ success: false, message: "Post not found" });
    }

    // Cascade delete
    await communityPostLikesCollection.deleteMany({ postId: postObjId });

    if (post.type === "course") {
      const course = await communityCoursesCollection.findOne({ postId: postObjId });
      if (course) {
        const courseId = course._id;
        await Promise.all([
          communityLessonsCollection.deleteMany({ courseId }),
          communityChaptersCollection.deleteMany({ courseId }),
          communityExamsCollection.deleteMany({ courseId }),
          communityExamAttemptsCollection.deleteMany({ courseId }),
          communityEnrollmentsCollection.deleteMany({ courseId }),
          communityProgressCollection.deleteMany({ courseId }),
          communityCertificatesCollection.deleteMany({ courseId }),
          communityCoursesCollection.deleteOne({ _id: courseId })
        ]);
      }
    }

    await communityPostsCollection.deleteOne({ _id: postObjId });
    return res.json({ success: true, message: "Post deleted" });
  } catch (error) {
    console.error("DELETE /admin/posts/:postId error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Get community statistics (admin only)
app.get("/admin/communities/stats", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Admin access required" });
    }

    const totalCommunities = await communityCollection.countDocuments({});
    const verifiedCommunities = await communityCollection.countDocuments({ isVerified: true });
    const totalPosts = await communityPostsCollection.countDocuments({});
    const totalCourses = await communityCoursesCollection.countDocuments({});
    const totalEnrollments = await communityEnrollmentsCollection.countDocuments({});
    const totalFollows = await communityFollowsCollection.countDocuments({});

    // Get recent communities
    const recentCommunities = await communityCollection
      .find({})
      .sort({ createdAt: -1 })
      .limit(5)
      .toArray();

    return res.json({
      success: true,
      data: {
        totalCommunities,
        verifiedCommunities,
        totalPosts,
        totalCourses,
        totalEnrollments,
        totalFollows,
        recentCommunities
      }
    });
  } catch (error) {
    console.error("GET /admin/communities/stats error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Start the serve
