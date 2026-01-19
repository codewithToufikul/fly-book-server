# 📚 Fly-Book Server

A comprehensive full-stack backend API server for the Fly-Book platform - an all-in-one social learning ecosystem that combines book sharing, e-learning, e-commerce, job marketplace, freelancing, and social networking features.

## 🌟 Overview

Fly-Book Server is a robust Node.js/Express.js backend that powers a multi-faceted platform designed to connect learners, educators, book enthusiasts, employers, and freelancers in Bangladesh and beyond. The platform supports real-time communication, course management, e-commerce transactions, and community-driven content.

## 🚀 Key Features

### 📖 Book Management & Sharing

- **Physical Book Exchange**: Users can list, search, and exchange physical books with location-based filtering
- **PDF Library**: Upload, store, and share PDF books with page count tracking
- **Book Translations**: Support for translated book collections
- **Book Transactions**: Track book lending and borrowing history
- **Location-based Search**: Find books near you using geospatial queries

### 👥 Community & Social Features

- **Community Creation**: Create and manage topic-based communities
- **Role-based Access**: Main admin, admin, editor, and member roles
- **Community Posts**: Share content, courses, and discussions within communities
- **Follow System**: Follow communities and track member engagement
- **Post Interactions**: Like, comment, and share community posts

### 🎓 Learning Management System (LMS)

- **Course Creation**: Build comprehensive courses with chapters and lessons
- **Multiple Content Types**: Support for video, audio, text, and PDF lessons
- **Exam System**: Create MCQ, written, and listening comprehension exams
- **Auto-grading**: Automatic grading for MCQ exams
- **Manual Grading**: Teacher dashboard for grading written and listening exams
- **Progress Tracking**: Monitor student progress through courses
- **Certificates**: Auto-generate PDF certificates upon course completion
- **Enrollment Management**: Track student enrollments and access control
- **Student Dashboard**: Comprehensive analytics for course instructors

### 💬 Real-time Messaging & Communication

- **Private Messaging**: One-on-one chat with real-time delivery
- **Channel System**: Group messaging channels
- **Typing Indicators**: Real-time typing status
- **Online Status**: Track user online/offline status
- **Message Notifications**: Real-time push notifications
- **Unread Message Tracking**: Count and manage unread messages

### 🛒 E-Commerce Platform

- **Product Management**: Full CRUD for products with categories
- **Shopping Cart**: Add, update, and remove items from cart
- **Order Processing**: Complete order management system
- **Seller Accounts**: Multi-vendor marketplace support
- **Product Search**: Text-based product search
- **Banners**: Promotional banner management
- **Address Management**: Multiple shipping addresses per user

### 💼 Job Marketplace

- **Job Postings**: Employers can post job opportunities
- **Job Applications**: Users can apply for jobs with resumes
- **Employer Profiles**: Dedicated employer account management
- **Job Search**: Search jobs by title, description, and filters
- **Application Tracking**: Monitor application status

### 🎯 Freelance Marketplace

- **Project Posting**: Clients can post freelance projects
- **Proposal System**: Freelancers submit proposals with bids
- **Project Management**: Track project status and milestones

### 💰 FlyWallet - Digital Wallet System

- **Coin System**: Internal currency (100 coins = 1 Taka)
- **Peer-to-peer Transfers**: Send coins to other users
- **Transaction History**: Complete audit trail of all transactions
- **Withdrawal System**: Cash out coins to real money
- **Shop Integration**: Use coins at partner shops
- **Shop Locations**: Location-based shop discovery

### 📝 Opinion & Content Sharing

- **Opinion Posts**: Share thoughts and opinions
- **Admin Posts**: Official announcements and content
- **AI-generated Posts**: Support for AI-assisted content
- **Thesis Sharing**: Academic thesis repository
- **Notes System**: Personal note-taking feature
- **Organization Profiles**: Institutional accounts

### 🔐 Authentication & User Management

- **JWT Authentication**: Secure token-based authentication
- **User Registration**: Email and phone number registration
- **Profile Management**: Comprehensive user profiles with images
- **Email Verification**: Nodemailer integration for email verification
- **Password Encryption**: bcrypt password hashing
- **Role-based Authorization**: Admin, seller, employer, and user roles
- **Profile Verification**: Verified user badges

### 🔔 Notification System

- **Real-time Notifications**: Socket.io powered instant notifications
- **Friend Requests**: Send and receive friend requests
- **Activity Notifications**: Course enrollments, likes, comments, etc.
- **Unread Tracking**: Mark notifications as read/unread

### 🌐 Additional Features

- **Translation API**: Google Translate integration for multi-language support
- **File Upload**: Cloudinary integration for images, videos, audio, and PDFs
- **Compression**: Response compression for better performance
- **CORS Support**: Configured for multiple frontend origins
- **Geolocation**: Location-based features for books and shops
- **Search Functionality**: Global search across books, products, jobs, and projects
- **Home Categories**: Curated content categories for homepage

## 🛠️ Technology Stack

### Core Technologies

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB (MongoDB Atlas)
- **Real-time**: Socket.io
- **Authentication**: JWT (jsonwebtoken)

### Cloud Services

- **File Storage**: Cloudinary (images, videos, audio, PDFs)
- **Email**: Nodemailer
- **SMS**: Twilio (optional)

### Key Libraries

- **bcryptjs**: Password hashing
- **multer**: File upload handling
- **multer-storage-cloudinary**: Cloudinary storage adapter
- **pdf-parse**: PDF text extraction
- **pdfkit**: PDF generation for certificates
- **axios**: HTTP client
- **compression**: Response compression
- **cors**: Cross-origin resource sharing
- **@vitalets/google-translate-api**: Translation service

## 📋 Prerequisites

- Node.js (v14 or higher)
- MongoDB Atlas account
- Cloudinary account
- Gmail account (for Nodemailer)
- npm or bun package manager

## ⚙️ Installation

1. **Clone the repository**

```bash
git clone https://github.com/yourusername/fly-book-server.git
cd fly-book-server
```

2. **Install dependencies**

```bash
npm install
# or
bun install
```

3. **Configure environment variables**

Create a `.env` file in the root directory:

```env
# MongoDB Configuration
DB_USER=your_mongodb_username
DB_PASS=your_mongodb_password

# JWT Secret
JWT_SECRET=your_jwt_secret_key
ACCESS_TOKEN_SECRET=your_access_token_secret

# Cloudinary Configuration
CLOUDINARY_CLOUD_NAME=your_cloudinary_cloud_name
CLOUDINARY_API_KEY=your_cloudinary_api_key
CLOUDINARY_API_SECRET=your_cloudinary_api_secret

# Email Configuration (Nodemailer)
EMAIL_USER=your_gmail_address
EMAIL_PASS=your_gmail_app_password

# Optional: Twilio (for SMS)
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_PHONE_NUMBER=your_twilio_phone_number

# Optional: AI/Search APIs
HUGGING_FACE_API_KEY=your_huggingface_api_key
GOOGLE_CUSTOM_SEARCH_API_KEY=your_google_api_key
GOOGLE_CUSTOM_SEARCH_ENGINE_ID=your_search_engine_id
GMINI_API_KEY=your_gemini_api_key

# Server Configuration
PORT=3000
NODE_ENV=production
```

4. **Start the development server**

```bash
npm run dev
```

5. **Start the production server**

```bash
node index.js
```

## 🌐 API Endpoints

### Health & Diagnostics

- `GET /` - API status check
- `GET /health` - Health check with database status
- `GET /diagnostics` - Detailed diagnostic information

### Authentication

- `POST /users/register` - User registration
- `POST /users/login` - User login
- `GET /profile` - Get user profile (requires auth)
- `PUT /profile/update` - Update profile
- `PUT /profile/cover/update` - Update cover image
- `PUT /profile/verification` - Update verification status
- `PUT /profile/updateDetails` - Update profile details

### Books

- `POST /upload` - Upload book (image/PDF)
- `GET /pdf-books` - Get all PDF books
- `GET /books` - Get all physical books
- `GET /books/:id` - Get book by ID
- `PUT /books/:id` - Update book
- `DELETE /books/:id` - Delete book
- `GET /books/search` - Search books

### Communities

- `POST /community-create` - Create community
- `GET /communities` - List all communities
- `GET /communities/:id` - Get community details
- `PATCH /communities/:id` - Update community
- `POST /communities/:id/follow` - Follow/unfollow community
- `GET /communities/:id/follow-status` - Check follow status
- `GET /my-communities` - Get user's communities
- `GET /communities/:id/permissions` - Get user permissions
- `POST /communities/:id/roles/add` - Add role to user
- `POST /communities/:id/roles/remove` - Remove role from user

### Community Posts

- `POST /communities/:id/posts` - Create post in community
- `GET /communities/:id/posts` - Get community posts
- `PUT /posts/:postId` - Edit post
- `DELETE /posts/:postId` - Delete post
- `POST /posts/:postId/like` - Like/unlike post
- `GET /posts/:postId/liked` - Check if user liked post

### Courses & Learning

- `POST /courses/:courseId/enroll` - Enroll in course
- `POST /courses/:courseId/enroll-user` - Enroll another user
- `GET /courses/:courseId/enrolled` - Check enrollment status
- `GET /courses/:courseId/outline` - Get course outline
- `GET /courses/:courseId/progress` - Get user progress
- `POST /courses/:courseId/lessons/:lessonId/complete` - Mark lesson complete
- `GET /posts/:postId/course` - Get course details from post

### Exams & Grading

- `GET /exams/:examId` - Get exam details
- `POST /exams/:examId/attempt` - Submit exam attempt
- `POST /exams/attempts/:attemptId/grade` - Grade exam attempt
- `GET /exams/attempts/ungraded` - Get ungraded attempts
- `GET /courses/:courseId/attempts` - Get all course attempts
- `GET /courses/:courseId/student-dashboard` - Student analytics

### Certificates

- `POST /courses/:courseId/certificate` - Generate certificate

### File Uploads

- `POST /upload/audio` - Upload audio file
- `POST /upload/video` - Upload video file
- `POST /upload` - Upload image/PDF

### E-Commerce

- `GET /products` - List products
- `POST /products` - Create product
- `GET /products/:id` - Get product details
- `PUT /products/:id` - Update product
- `DELETE /products/:id` - Delete product
- `GET /cart` - Get user's cart
- `POST /cart` - Add to cart
- `PUT /cart/:id` - Update cart item
- `DELETE /cart/:id` - Remove from cart
- `POST /orders` - Create order
- `GET /orders` - Get user orders
- `GET /orders/:id` - Get order details

### Jobs

- `GET /jobs` - List jobs
- `POST /jobs` - Create job posting
- `GET /jobs/:id` - Get job details
- `PUT /jobs/:id` - Update job
- `DELETE /jobs/:id` - Delete job
- `POST /jobs/:id/apply` - Apply for job
- `GET /applications` - Get user applications

### Freelance Projects

- `GET /projects` - List projects
- `POST /projects` - Create project
- `GET /projects/:id` - Get project details
- `PUT /projects/:id` - Update project
- `DELETE /projects/:id` - Delete project
- `POST /projects/:id/proposal` - Submit proposal

### FlyWallet

- `POST /api/transfer-coins` - Transfer coins to user
- `GET /api/transfer-history` - Get transfer history
- `GET /api/admin/all-coin-transfers` - Admin: all transfers
- `POST /api/withdraws` - Request withdrawal
- `GET /api/withdraws` - Get withdrawal requests
- `PUT /api/withdraws/:id` - Update withdrawal status

### Shops

- `GET /api/shops` - List shops
- `POST /api/shops` - Create shop
- `GET /api/shops/:id` - Get shop details
- `PUT /api/shops/:id` - Update shop
- `DELETE /api/shops/:id` - Delete shop
- `GET /api/locations` - Get shop locations

### Messaging

- `GET /messages` - Get user messages
- `POST /messages` - Send message
- `PUT /messages/:id/read` - Mark message as read
- `GET /messages/unread` - Get unread count

### Notifications

- `GET /notifications` - Get notifications
- `POST /notifications` - Create notification
- `PUT /notifications/:id/read` - Mark as read
- `GET /notifications/unread` - Get unread count

### Opinions & Content

- `GET /opinions` - Get opinions
- `POST /opinions` - Create opinion
- `GET /admin-posts` - Get admin posts
- `POST /admin-posts` - Create admin post
- `GET /home-category` - Get home categories

### Utilities

- `POST /api/translate` - Translate text
- `GET /search` - Global search

## 🔌 WebSocket Events

### Client → Server

- `joinRoom` - Join user's personal room
- `joinUser` - Join and set online status
- `sendRequest` - Send friend request notification
- `sendMessage` - Send chat message
- `typing` - Broadcast typing status
- `disconnect` - Handle user disconnect

### Server → Client

- `notification` - Receive real-time notification
- `newMessage` - Receive new message
- `typing` - Receive typing indicator
- `userStatusChange` - User online/offline status

## 📊 Database Collections

The server uses MongoDB with the following collections:

- `usersCollections` - User accounts and profiles
- `bookCollections` - Physical books
- `pdfCollections` - PDF books
- `opinionCollections` - User opinions
- `adminPostCollections` - Admin posts
- `adminThesisCollections` - Thesis documents
- `adminAiPostCollections` - AI-generated posts
- `messagesCollections` - Chat messages
- `notifyCollections` - Notifications
- `noteCollections` - User notes
- `organizationCollections` - Organizations
- `homeCategoryCollection` - Home page categories
- `coinTransferCollections` - Wallet transactions
- `communityCollection` - Communities
- `communityFollowsCollection` - Community follows
- `communityPostsCollection` - Community posts
- `communityPostLikesCollection` - Post likes
- `communityCoursesCollection` - Courses
- `communityChaptersCollection` - Course chapters
- `communityLessonsCollection` - Course lessons
- `communityExamsCollection` - Exams
- `communityExamAttemptsCollection` - Exam submissions
- `communityProgressCollection` - Course progress
- `communityEnrollmentsCollection` - Course enrollments
- `communityCertificatesCollection` - Certificates
- `productsCollection` - E-commerce products
- `productsCategories` - Product categories
- `cartsCollection` - Shopping carts
- `ordersCollection` - Orders
- `addressesCollection` - Shipping addresses
- `sellerCollections` - Seller accounts
- `bannersCollection` - Promotional banners
- `withdrawsCollection` - Withdrawal requests
- `jobsCollection` - Job postings
- `jobApplicationsCollection` - Job applications
- `employersCollection` - Employer accounts
- `projectsCollection` - Freelance projects
- `proposalsCollection` - Project proposals
- `locationsCollection` - Shop locations
- `shopsCollection` - Partner shops
- `channelsCollection` - Message channels
- `channelMessagesCollection` - Channel messages
- `coursesCollection` - Legacy courses

## 🚀 Deployment

### Vercel Deployment

The project is configured for Vercel serverless deployment:

1. Install Vercel CLI:

```bash
npm i -g vercel
```

2. Deploy:

```bash
vercel
```

3. Set environment variables in Vercel dashboard

The `vercel.json` configuration is already included.

### VPS/Traditional Hosting

1. Install Node.js on your server
2. Clone the repository
3. Install dependencies
4. Set up environment variables
5. Use PM2 for process management:

```bash
npm install -g pm2
pm2 start index.js --name fly-book-server
pm2 save
pm2 startup
```

### MongoDB Atlas Setup

1. Create a MongoDB Atlas account
2. Create a new cluster
3. Add your server IP to Network Access (or use 0.0.0.0/0 for testing)
4. Create a database user
5. Get connection string and add to `.env`

### Cloudinary Setup

1. Create a Cloudinary account
2. Get your cloud name, API key, and API secret
3. Add credentials to `.env`

## 🔒 Security Features

- JWT-based authentication
- bcrypt password hashing
- CORS configuration
- Environment variable protection
- Input validation
- Role-based access control
- Token expiration handling
- Secure file upload validation

## ⚡ Performance Optimizations

- Response compression (gzip/brotli)
- MongoDB connection pooling
- Database indexing on frequently queried fields
- Cloudinary CDN for media delivery
- Efficient query projections
- Connection retry logic with exponential backoff

## 🐛 Error Handling

- Comprehensive try-catch blocks
- Graceful database connection failures
- Detailed error logging
- User-friendly error messages
- Development vs production error responses
- Health check endpoints for monitoring

## 📝 Environment Variables Reference

| Variable                       | Description                          | Required |
| ------------------------------ | ------------------------------------ | -------- |
| `DB_USER`                      | MongoDB username                     | Yes      |
| `DB_PASS`                      | MongoDB password                     | Yes      |
| `JWT_SECRET`                   | JWT signing secret                   | Yes      |
| `ACCESS_TOKEN_SECRET`          | Alternative JWT secret               | Yes      |
| `CLOUDINARY_CLOUD_NAME`        | Cloudinary cloud name                | Yes      |
| `CLOUDINARY_API_KEY`           | Cloudinary API key                   | Yes      |
| `CLOUDINARY_API_SECRET`        | Cloudinary API secret                | Yes      |
| `EMAIL_USER`                   | Gmail address for emails             | Optional |
| `EMAIL_PASS`                   | Gmail app password                   | Optional |
| `PORT`                         | Server port (default: 3000)          | No       |
| `NODE_ENV`                     | Environment (development/production) | No       |
| `TWILIO_ACCOUNT_SID`           | Twilio account SID                   | Optional |
| `TWILIO_AUTH_TOKEN`            | Twilio auth token                    | Optional |
| `HUGGING_FACE_API_KEY`         | HuggingFace API key                  | Optional |
| `GOOGLE_CUSTOM_SEARCH_API_KEY` | Google search API key                | Optional |
| `GMINI_API_KEY`                | Gemini API key                       | Optional |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is proprietary software. All rights reserved.

## 👨‍💻 Author

**Tofikul Islam**

## 🆘 Support

For issues and questions:

- Create an issue in the repository
- Contact: [Your contact information]

## 🔄 Version History

- **v1.0.0** - Initial release with full feature set

## 🎯 Roadmap

- [ ] GraphQL API support
- [ ] Redis caching layer
- [ ] Advanced analytics dashboard
- [ ] Mobile app API optimization
- [ ] Microservices architecture migration
- [ ] AI-powered recommendations
- [ ] Video streaming optimization
- [ ] Multi-language support expansion

---

**Built with ❤️ for the learning community**
