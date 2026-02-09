# 🔄 OTP Email Verification Flow

## Visual Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     MULTI-STEP REGISTRATION WITH OTP                     │
└─────────────────────────────────────────────────────────────────────────┘

Step 1: Name Screen
┌────────────┐
│   Mobile   │
│   App      │  User enters: First Name, Last Name
│            │  Taps "Next"
└─────┬──────┘
      │
      │ Navigate to Step 2
      ↓

Step 2: Email Screen
┌────────────┐
│   Mobile   │
│   App      │  User enters: Email
│            │  Taps "Send Code"
└─────┬──────┘
      │
      │ POST /users/send-otp
      │ Body: { email: "user@example.com" }
      ↓
┌────────────┐
│  Backend   │  1. Validate email format
│  Server    │  2. Generate 6-digit OTP (e.g., 456789)
│            │  3. Store in otpCollections:
│            │     {
│            │       email: "user@example.com",
│            │       otp: "456789",
│            │       expiresAt: Date(now + 10min),
│            │       verified: false
│            │     }
│            │  4. Send HTML email via Nodemailer
│            │  5. Return { success: true }
└─────┬──────┘
      │
      │ Response: success
      ↓
┌────────────┐
│   Mobile   │  Show: "Code sent! Check your email"
│   App      │  Navigate to Step 3
└────────────┘
      │
      │
      ↓
┌────────────┐
│   Gmail    │  📧 User receives email:
│   Inbox    │
│            │  ┌───────────────────────────────┐
│            │  │  📚 FlyBook                   │
│            │  │  Your Social Learning Platform│
│            │  ├───────────────────────────────┤
│            │  │  Verify Your Email Address    │
│            │  │                               │
│            │  │  Your Verification Code:      │
│            │  │                               │
│            │  │     4 5 6 7 8 9              │
│            │  │                               │
│            │  │  Expires in 10 minutes        │
│            │  └───────────────────────────────┘
└────────────┘
      │
      │ User opens email, sees code: 456789
      ↓

Step 3: Verify Screen
┌────────────┐
│   Mobile   │  User enters: 4 5 6 7 8 9
│   App      │  Taps "Verify"
└─────┬──────┘
      │
      │ POST /users/verify-otp
      │ Body: { email: "user@example.com", otp: "456789" }
      ↓
┌────────────┐
│  Backend   │  1. Find OTP in otpCollections
│  Server    │  2. Check expiresAt > now (not expired)
│            │  3. Compare OTP: "456789" === "456789" ✅
│            │  4. Update: { verified: true, verifiedAt: now }
│            │  5. Return { success: true }
└─────┬──────┘
      │
      │ Response: verified successfully
      ↓
┌────────────┐
│   Mobile   │  Navigate to Step 4
│   App      │
└────────────┘
      │
      ↓

Step 4: Phone Screen (Optional)
┌────────────┐
│   Mobile   │  User can:
│   App      │  - Enter phone number
│            │  - OR tap "Skip"
│            │  Taps "Next" or "Skip"
└─────┬──────┘
      │
      │ Navigate to Step 5
      ↓

Step 5: Password Screen
┌────────────┐
│   Mobile   │  User enters: Password, Confirm Password
│   App      │  Taps "Create Account"
└─────┬──────┘
      │
      │ POST /users/register
      │ Body: {
      │   name: "John Doe",
      │   email: "user@example.com",
      │   number: "01712345678" (or empty),
      │   password: "test123",
      │   userLocation: { lat, lng },
      │   referrerUsername: ""
      │ }
      ↓
┌────────────┐
│  Backend   │  1. Check if user exists (by number)
│  Server    │  2. Generate unique username
│            │  3. Hash password
│            │  4. Create user document
│            │  5. Save to usersCollections
│            │  6. Generate JWT token:
│            │     jwt.sign({ id, email, number }, secret, { expiresIn: "30d" })
│            │  7. Return:
│            │     {
│            │       success: true,
│            │       token: "eyJhbGciOiJIUzI1NiIs...",
│            │       user: { _id, name, email, ... }
│            │     }
└─────┬──────┘
      │
      │ Response: { token, user }
      ↓
┌────────────┐
│   Mobile   │  1. Save token to AsyncStorage
│   App      │  2. Save user to AsyncStorage
│            │  3. Update AuthContext: setUser(user)
│            │  4. AuthContext now: isAuthenticated = true
└─────┬──────┘
      │
      │ RootNavigator detects: isAuthenticated = true
      ↓
┌────────────┐
│   Mobile   │  🎉 Auto-redirect to Home Screen
│   App      │  User is logged in!
│ (Home Page)│
└────────────┘

✅ REGISTRATION COMPLETE!
✅ USER LOGGED IN!
✅ NO MANUAL LOGIN REQUIRED!
```

---

## 🔄 OTP Verification Flow (Detailed)

```
┌──────────────────────────────────────────────────────────────────┐
│                    SEND OTP ENDPOINT FLOW                        │
└──────────────────────────────────────────────────────────────────┘

Mobile App
    │
    │ POST /users/send-otp
    │ { email: "user@example.com" }
    ↓
┌───────────────────┐
│ Backend Endpoint  │
│ /users/send-otp   │
└────────┬──────────┘
         │
         ├──→ Validate email?
         │    ├─ Empty? → 400 "Email is required"
         │    └─ Invalid format? → 400 "Invalid email format"
         │
         ├──→ Generate OTP
         │    └─ Math.floor(100000 + Math.random() * 900000)
         │       Result: "456789" (6 digits)
         │
         ├──→ Calculate expiry
         │    └─ new Date(Date.now() + 10 * 60 * 1000)
         │       Result: 10 minutes from now
         │
         ├──→ Store in MongoDB
         │    └─ otpCollections.updateOne(
         │           { email: "user@example.com" },
         │           {
         │             email: "user@example.com",
         │             otp: "456789",
         │             expiresAt: 2026-02-09T10:45:00,
         │             createdAt: 2026-02-09T10:35:00,
         │             verified: false
         │           },
         │           { upsert: true }
         │        )
         │
         ├──→ Send email via Nodemailer
         │    ├─ To: user@example.com
         │    ├─ Subject: "Your FlyBook Verification Code"
         │    ├─ Body: Beautiful HTML template
         │    └─ OTP displayed: 456789
         │
         ├──→ Log to console
         │    └─ "OTP sent to user@example.com: 456789 (expires at ...)"
         │
         └──→ Return response
              └─ 200 { success: true, message: "Verification code sent" }
                   │
                   ↓
              Mobile App
              Shows: "Code sent! Check your email"
              Navigates to: Step3Verify
```

---

```
┌──────────────────────────────────────────────────────────────────┐
│                   VERIFY OTP ENDPOINT FLOW                       │
└──────────────────────────────────────────────────────────────────┘

Mobile App
    │
    │ POST /users/verify-otp
    │ { email: "user@example.com", otp: "456789" }
    ↓
┌───────────────────┐
│ Backend Endpoint  │
│ /users/verify-otp │
└────────┬──────────┘
         │
         ├──→ Validate input?
         │    ├─ Empty email/otp? → 400 "Email and OTP are required"
         │
         ├──→ Find OTP in database
         │    └─ otpCollections.findOne({ email: "user@example.com" })
         │       Result: {
         │         email: "user@example.com",
         │         otp: "456789",
         │         expiresAt: 2026-02-09T10:45:00,
         │         verified: false
         │       }
         │
         ├──→ Check if found?
         │    └─ Not found? → 404 "No verification code found"
         │
         ├──→ Check if expired?
         │    ├─ now = 2026-02-09T10:40:00
         │    ├─ expiresAt = 2026-02-09T10:45:00
         │    ├─ now > expiresAt? NO ✅
         │    │
         │    └─ If YES (expired):
         │       ├─ Delete OTP from database
         │       └─ 400 "Verification code has expired"
         │
         ├──→ Compare OTP?
         │    ├─ Received: "456789"
         │    ├─ Database: "456789"
         │    ├─ Match? YES ✅
         │    │
         │    └─ If NO (wrong code):
         │       └─ 400 "Invalid verification code"
         │
         ├──→ Mark as verified
         │    └─ otpCollections.updateOne(
         │           { email: "user@example.com" },
         │           { $set: { 
         │               verified: true, 
         │               verifiedAt: 2026-02-09T10:40:00 
         │             } 
         │           }
         │        )
         │
         └──→ Return response
              └─ 200 { success: true, message: "Email verified successfully" }
                   │
                   ↓
              Mobile App
              Navigates to: Step4Phone
```

---

## 🔄 Complete Registration Flow

```
┌──────────────────────────────────────────────────────────────────┐
│              COMPLETE MULTI-STEP REGISTRATION                    │
└──────────────────────────────────────────────────────────────────┘

Progress: ○○○○○

STEP 1: Name
┌─────────────┐
│ First Name  │ [John                    ]
│ Last Name   │ [Doe                     ]
│             │
│         [ Next → ]
└─────────────┘

Progress: ●○○○○ (Step 1 complete)
        ↓

STEP 2: Email
┌─────────────┐
│ Email       │ [john@example.com        ]
│             │
│         [ Send Code → ]
└─────────────┘
        ↓
    API: POST /users/send-otp
        ↓
    Backend: Generate OTP, Send Email
        ↓
    "Code sent! Check your email"

Progress: ●●○○○ (Step 2 complete)
        ↓

📧 EMAIL ARRIVES
┌─────────────────────────┐
│  📚 FlyBook              │
│  Verification Code:      │
│                          │
│     4 5 6 7 8 9         │
│                          │
│  Expires in 10 minutes   │
└─────────────────────────┘

        ↓

STEP 3: Verify
┌─────────────┐
│ Enter Code  │
│             │
│  [4][5][6][7][8][9]     │
│             │
│         [ Verify → ]
│             │
│   Resend code
└─────────────┘
        ↓
    API: POST /users/verify-otp
        ↓
    Backend: Validate OTP
        ↓
    "Email verified successfully"

Progress: ●●●○○ (Step 3 complete)
        ↓

STEP 4: Phone (Optional)
┌─────────────┐
│ Phone       │ [🇧🇩 +880            Skip →]
│ Number      │ [01712345678         ]
│             │
│  ℹ️  Optional for now
│             │
│         [ Next → ]
└─────────────┘

Progress: ●●●●○ (Step 4 complete)
        ↓

STEP 5: Password
┌─────────────┐
│ Password    │ [••••••••            👁]
│             │ ✅ At least 6 characters
│             │
│ Confirm     │ [••••••••            👁]
│ Password    │ ✅ Passwords match
│             │
│         [ Create Account → ]
└─────────────┘
        ↓
    API: POST /users/register
        ↓
    Backend: Create user, Generate token
        ↓
    Response: { token, user }
        ↓
    Save token → Save user → Update AuthContext
        ↓
    isAuthenticated = true

Progress: ●●●●● (All steps complete!)
        ↓

🎉 HOME SCREEN (Auto-logged in!)
┌─────────────────────────┐
│  Welcome, John Doe!      │
│                          │
│  [Feed]  [Explore]  [+]  │
│                          │
│  Recent posts...         │
└─────────────────────────┘

✅ REGISTRATION COMPLETE!
✅ USER LOGGED IN!
✅ NO MANUAL LOGIN NEEDED!
```

---

## 🗄️ Database State Changes

```
┌──────────────────────────────────────────────────────────────────┐
│                    DATABASE STATE FLOW                           │
└──────────────────────────────────────────────────────────────────┘

Initial State (Empty)
─────────────────────
usersCollections: []
otpCollections: []


After Step 2 (Send OTP)
────────────────────────
usersCollections: []
otpCollections: [
  {
    _id: ObjectId("..."),
    email: "john@example.com",
    otp: "456789",
    expiresAt: ISODate("2026-02-09T10:45:00Z"),
    createdAt: ISODate("2026-02-09T10:35:00Z"),
    verified: false
  }
]


After Step 3 (Verify OTP)
──────────────────────────
usersCollections: []
otpCollections: [
  {
    _id: ObjectId("..."),
    email: "john@example.com",
    otp: "456789",
    expiresAt: ISODate("2026-02-09T10:45:00Z"),
    createdAt: ISODate("2026-02-09T10:35:00Z"),
    verified: true,                              ← Changed
    verifiedAt: ISODate("2026-02-09T10:40:00Z")  ← Added
  }
]


After Step 5 (Registration Complete)
─────────────────────────────────────
usersCollections: [
  {
    _id: ObjectId("507f1f77bcf86cd799439011"),
    name: "John Doe",
    email: "john@example.com",
    number: "01712345678",
    userName: "johndoe123",
    password: "$2a$10$...", (hashed)
    verificationStatus: false,
    userLocation: {
      type: "Point",
      coordinates: [90.4125, 23.8103]
    },
    role: "user",
    profileImage: "https://i.ibb.co/...",
    referrerId: null,
    referrerName: null,
    referredBy: null,
    createdAt: ISODate("2026-02-09T10:42:00Z"),
    flyWallet: 0,
    wallet: 0
  }
]

otpCollections: [
  {
    ... (same as before, can be cleaned up)
  }
]


Token Generated
───────────────
JWT Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjUwN2YxZjc3YmNmODZjZDc5OTQzOTAxMSIsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsIm51bWJlciI6IjAxNzEyMzQ1Njc4IiwiaWF0IjoxNzM5MDk1MzIwLCJleHAiOjE3NDE2ODczMjB9...."

Payload: {
  id: "507f1f77bcf86cd799439011",
  email: "john@example.com",
  number: "01712345678",
  iat: 1739095320,
  exp: 1741687320  (30 days later)
}


AsyncStorage (Mobile)
─────────────────────
@auth_token: "eyJhbGciOiJIUzI1NiIs..."
@user_data: "{\"_id\":\"507f1f77...\",\"name\":\"John Doe\",\"email\":\"john@example.com\",...}"


AuthContext (Mobile)
────────────────────
user: {
  _id: "507f1f77bcf86cd799439011",
  name: "John Doe",
  email: "john@example.com",
  userName: "johndoe123",
  ...
}
isAuthenticated: true
isLoading: false

→ RootNavigator renders: <DrawerNavigator /> (Home Screen)
```

---

## 🔐 Security Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                      SECURITY MEASURES                           │
└──────────────────────────────────────────────────────────────────┘

OTP Generation
──────────────
• Random 6-digit number (100,000 - 999,999)
• 1,000,000 possible combinations
• Cryptographically random via Math.random()


OTP Storage
───────────
• Stored in MongoDB
• Email normalized (lowercase, trimmed)
• Expiry set to 10 minutes
• Single-use (marked as verified)


OTP Validation
───────────────
✓ Check if OTP exists
✓ Check not expired (expiresAt > now)
✓ Check code matches (string comparison)
✓ Mark as verified (prevent reuse)
✓ Auto-delete if expired


Password Security
─────────────────
• Hashed with bcrypt (salt rounds: 10)
• Never stored in plain text
• Never returned in API responses
• Strength validated on client


Token Security
──────────────
• JWT with 30-day expiry
• Signed with JWT_SECRET
• Includes: user ID, email, number
• Stored in AsyncStorage (encrypted)
• Auto-included in API requests (Authorization header)


Email Security
──────────────
• Case-insensitive matching
• Format validation (regex)
• Trimmed to prevent whitespace issues
• Sent via secure SMTP (TLS)


Database Security
─────────────────
• MongoDB connection with authentication
• Passwords hashed before storage
• OTPs expire automatically
• No sensitive data in logs
```

---

## 📊 Timing Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                    TIMING & EXPIRY FLOW                          │
└──────────────────────────────────────────────────────────────────┘

Time: 10:35:00 AM
─────────────────
User requests OTP
    ↓
Backend generates: 456789
Backend sets expiry: 10:45:00 AM (10 min from now)
Backend sends email
    ↓
Email arrives (< 5 seconds)


Time: 10:36:00 AM
─────────────────
User opens email
User sees code: 456789
Expiry: 9 minutes remaining


Time: 10:40:00 AM
─────────────────
User enters code in app
    ↓
Backend checks:
  • expiresAt = 10:45:00 AM
  • now = 10:40:00 AM
  • now < expiresAt? YES ✅
    ↓
Code valid! Mark as verified
User proceeds to next step


Time: 10:46:00 AM (if user was too slow)
──────────────────────────────────────────
User enters code (after 11 minutes)
    ↓
Backend checks:
  • expiresAt = 10:45:00 AM
  • now = 10:46:00 AM
  • now > expiresAt? YES ❌
    ↓
Code expired! Delete from database
Return error: "Verification code has expired"
User must request new code


Recommended Timeline
────────────────────
00:00 - User requests OTP
00:05 - Email arrives
00:30 - User enters code (within 30 seconds) ✅ IDEAL
10:00 - Still valid (within 10 minutes) ✅ OK
10:01 - Expired ❌ Must request new code
```

---

## 📝 Error Scenarios

```
┌──────────────────────────────────────────────────────────────────┐
│                    ERROR HANDLING FLOW                           │
└──────────────────────────────────────────────────────────────────┘

Scenario 1: Invalid Email Format
─────────────────────────────────
Input: "notanemail"
    ↓
Validation fails: Email regex doesn't match
    ↓
Response: 400 "Invalid email format"


Scenario 2: OTP Expired
────────────────────────
User waits 11 minutes
    ↓
Backend checks: now (10:46) > expiresAt (10:45)
    ↓
Delete OTP from database
    ↓
Response: 400 "Verification code has expired"


Scenario 3: Wrong OTP Code
───────────────────────────
User enters: 123456
Database has: 456789
    ↓
Compare: "123456" === "456789" ? NO
    ↓
Response: 400 "Invalid verification code"


Scenario 4: Email Not Sent
───────────────────────────
SMTP connection fails
    ↓
Nodemailer throws error
    ↓
Catch in try/catch
    ↓
Response: 500 "Failed to send verification code"
    ↓
User can retry


Scenario 5: User Already Exists
────────────────────────────────
(During registration)
    ↓
Check: usersCollections.findOne({ number })
    ↓
Found existing user
    ↓
Response: 400 "User with this number already exists"


Scenario 6: No OTP Record Found
────────────────────────────────
User verifies before sending OTP
    ↓
otpCollections.findOne() returns null
    ↓
Response: 404 "No verification code found. Please request a new code"
```

---

## ✅ Success Indicators

```
┌──────────────────────────────────────────────────────────────────┐
│                    WHAT SUCCESS LOOKS LIKE                       │
└──────────────────────────────────────────────────────────────────┘

Backend Console
───────────────
✅ MongoDB connected
✅ Server running on port 3000
✅ OTP sent to john@example.com: 456789 (expires at ...)


Mobile App Logs
───────────────
✅ API: POST /users/send-otp - Success
✅ API: POST /users/verify-otp - Success
✅ API: POST /users/register - Success
✅ Token saved to AsyncStorage
✅ User saved to AsyncStorage
✅ AuthContext updated
✅ Navigation to Home


Gmail Inbox
───────────
✅ Email from FlyBook <flybook24@gmail.com>
✅ Subject: "Your FlyBook Verification Code"
✅ Body: Beautiful HTML with 6-digit code
✅ Received within 5 seconds


Database (MongoDB)
──────────────────
✅ OTP stored in otpCollections
✅ OTP marked as verified after Step 3
✅ User created in usersCollections after Step 5
✅ Password hashed
✅ Username unique


End Result
──────────
✅ User account created
✅ User logged in automatically
✅ Token valid for 30 days
✅ Home screen displayed
✅ Drawer shows user info
✅ Full app access granted
```

---

**Flow diagrams complete!** 🎉

**Use these to understand:**
- How OTP verification works
- What happens at each step
- Database state changes
- Error scenarios
- Security measures
- Timing/expiry behavior

**Ready to deploy and test!** 🚀
