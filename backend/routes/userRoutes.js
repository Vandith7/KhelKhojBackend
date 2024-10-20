const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const db = require('../db');
const moment = require('moment');
const otpGenerator = require("otp-generator");
const nodemailer = require("nodemailer");
require('dotenv').config();



const salt = 10;
const userTokenSecretKey = process.env.USER_JWT_KEY;

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/'); // Save uploaded files to the 'uploads' directory
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname)); // Rename file to prevent name conflicts
    }
});

// Initialize multer upload middleware
const upload = multer({ storage: storage });
const otpStore = {};
const forgotPasswordOtpStore = {};

// Send OTP for forgot password via email
const sendForgotPasswordOTPByEmail = (name, email, otp) => {
    // Use your email sending configuration here
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.APP_USER,
            pass: process.env.APP_PASS,
        },
    });

    const mailOptions = {
        from: process.env.APP_USER,
        to: email,
        subject: "Khel-Khoj Forgot Password OTP",
        html: `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Khel-Khoj Forgot Password OTP</title>
        </head>
        <body style="font-family: Quicksand, sans-serif; background-color: #f4f4f4; padding: 20px;">
        
            <div style="background-color: #fff; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);">
                <h1 style="color: #f19006; text-align: center;">Khel-Khoj</h1>
                <h2 style=" text-align: center;">Forgot Password OTP</h2>
                <h3 style="font-size: 16px;">Dear ${name},</h3>
                <p style="font-size: 16px; margin-top: 20px;">Your OTP for resetting your Khel-Khoj user account password is: <strong>${otp}</strong></p>
                <p style="font-size: 16px; margin-top: 20px;">Please use this OTP to reset your password.</p>
                <p style="font-size: 16px; margin-top: 20px;">If you didn't request this OTP, please ignore this email.</p>
                <p style="font-size: 16px; margin-top: 20px;">Thanks,<br/>The Khel-Khoj Team</p>
            </div>
        
        </body>
        </html>
        `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log("Error sending email:", error);
        } else {
            console.log("Email sent:", info.response);
        }
    });
};

const sendPasswordChangeSuccess = (name, email) => {
    // Use your email sending configuration here
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.APP_USER,
            pass: process.env.APP_PASS,
        },
    });

    const mailOptions = {
        from: process.env.APP_USER,
        to: email,
        subject: "Khel-Khoj User Account Password Change Successful",
        html: `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Khel-Khoj Password Change Success</title>
        </head>
        <body style="font-family: Quicksand, sans-serif; background-color: #f4f4f4; padding: 20px;">
        
            <div style="background-color: #fff; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);">
                <h1 style="color: #f19006; text-align: center;">Khel-Khoj</h1>
                <h2 style=" text-align: center;">Password Change Successful</h2>
                <h3 style="font-size: 16px;">Dear ${name},</h3>
                <p style="font-size: 16px; margin-top: 20px;">Your Khel-Khoj user account password has been successfully changed.</p>
                <p style="font-size: 16px; margin-top: 20px;">If you didn't initiate this change, please contact us immediately.</p>
                <p style="font-size: 16px; margin-top: 20px;">Thanks,<br/>The Khel-Khoj Team</p>
            </div>
        
        </body>
        </html>
        `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log("Error sending email:", error);
        } else {
            console.log("Email sent:", info.response);
        }
    });
};

// Route for requesting OTP for forgot password
router.post("/forgot-password", (req, res) => {
    const { email } = req.body;

    // Check if email exists in the database
    const checkEmailQuery = "SELECT * FROM users WHERE email = ?";
    db.query(checkEmailQuery, [email], (err, results) => {
        if (err) {
            return res.status(500).json({ error: "Error checking email existence" });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: "Email not found" });
        }
        const { name } = results[0];
        // Generate OTP with only numbers
        const otp = otpGenerator.generate(6, { upperCaseAlphabets: false, specialChars: false, lowerCaseAlphabets: false });
        forgotPasswordOtpStore[email] = otp;
        sendForgotPasswordOTPByEmail(name, email, otp);
        res.json({ status: "OTP sent successfully" });
    });
});

// Route for resetting password using OTP
router.post("/reset-password", (req, res) => {
    const { email, otp, password } = req.body;

    // Check if newPassword field is provided in the request body
    if (!password) {
        return res.status(400).json({ error: "New password is required" });
    }

    if (!forgotPasswordOtpStore[email] || forgotPasswordOtpStore[email] !== otp) {
        return res.status(400).json({ error: "Invalid OTP" });
    }

    // Fetch the user's name from the database
    const getNameQuery = "SELECT name FROM users WHERE email = ?";
    db.query(getNameQuery, [email], (nameErr, nameResult) => {
        if (nameErr || nameResult.length === 0) {
            return res.status(500).json({ error: "Error fetching user's name" });
        }

        const name = nameResult[0].name;

        // Clear OTP after successful verification
        delete forgotPasswordOtpStore[email];

        // Hash the new password
        bcrypt.hash(password.toString(), salt, (hashErr, hash) => {
            if (hashErr) {
                return res.status(500).json({ error: "Error hashing password" });
            }

            // Update the password in the database
            const updatePasswordQuery = "UPDATE users SET password = ? WHERE email = ?";
            db.query(updatePasswordQuery, [hash, email], (updateErr, result) => {
                if (updateErr) {
                    return res.status(500).json({ error: "Error updating password" });
                }
                // Send password change success email
                sendPasswordChangeSuccess(name, email);
                res.json({ status: "Success" });
            });
        });
    });
});


// Send OTP via email
const sendOTPByEmail = (email, name, otp) => {
    // Use your email sending configuration here
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.APP_USER,
            pass: process.env.APP_PASS,
        },
    });

    const mailOptions = {
        from: process.env.APP_USER,
        to: email,
        subject: "Khel-Khoj OTP Verification",
        html: `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Khel-Khoj OTP Verification</title>
        </head>
        <body style="font-family: Quicksand, sans-serif; background-color: #f4f4f4; padding: 20px;">
        
            <div style="background-color: #fff; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);">
                <h1 style="color: #f19006; text-align: center;">Khel-Khoj</h1>
                <h2 style=" text-align: center;">OTP Verification</h2>
                <h3 style="font-size: 16px;">Dear ${name},</h3>
                <p style="font-size: 16px;">Your OTP for user registration with Khel-Khoj is: <strong>${otp}</strong></p>
                <p style="font-size: 16px; margin-top: 20px;">Please use this OTP to complete your registration process.</p>
                <p style="font-size: 16px; margin-top: 20px;">If you didn't request this OTP, please ignore this email.</p>
                <p style="font-size: 16px; margin-top: 20px;">Thanks,<br/>The Khel-Khoj Team</p>
            </div>
        
        </body>
        </html>
        `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log("Error sending email:", error);
        } else {
            console.log("Email sent:", info.response);
        }
    });
};

const sendRegistrationSuccessByEmail = (name, email) => {
    // Use your email sending configuration here
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.APP_USER,
            pass: process.env.APP_PASS,
        },
    });

    const mailOptions = {
        from: process.env.APP_USER,
        to: email,
        subject: "Khel-Khoj Registration Successful",
        html: `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Khel-Khoj Registration Successful</title>
        </head>
        <body style="font-family: Quicksand, sans-serif; background-color: #f4f4f4; padding: 20px;">
        
            <div style="background-color: #fff; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);">
                <h1 style="color: #f19006; text-align: center;">Khel-Khoj</h1>
                <h2 style="text-align: center;">User Registration Successful</h2>
                <h3 style="font-size: 16px;">Dear ${name},</h3>
                <p style="font-size: 16px; margin-top: 20px;">Congratulations! You have successfully registered with Khel-Khoj.</p>
                <p style="font-size: 16px; margin-top: 20px;">You can now explore our platform and enjoy our services.</p>
                <p style="font-size: 16px; margin-top: 20px;">Thanks,<br/>The Khel-Khoj Team</p>
            </div>
        
        </body>
        </html>
        `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log("Error sending email:", error);
        } else {
            console.log("Email sent:", info.response);
        }
    });
};


router.post("/send-otp", (req, res) => {
    const { name, email } = req.body;

    // Check if email or name already exists in the database
    const checkQuery = "SELECT * FROM users WHERE email = ? OR name = ?";
    db.query(checkQuery, [email, name], (err, results) => {
        if (err) {
            return res.status(500).json({ error: "Error checking existence" });
        }

        for (let i = 0; i < results.length; i++) {
            if (results[i].email === email) {
                return res.status(400).json({ error: "Email already in use" });
            }
            if (results[i].name === name) {
                return res.status(400).json({ error: "User name already in use" });
            }
        }

        // Generate OTP with only numbers
        const otp = otpGenerator.generate(6, { upperCaseAlphabets: false, specialChars: false, lowerCaseAlphabets: false });
        otpStore[email] = otp;
        sendOTPByEmail(email, name, otp);
        res.json({ status: "OTP sent successfully" });
    });
});

// Verify OTP and register user
router.post("/register", upload.single('profile_photo'), (req, res) => {
    console.log("hii")
    const { name, email, gender, city, password, otp } = req.body;
    const profile_photo = req.body.profile_photo;

    if (!otpStore[email] || otpStore[email] !== otp) {
        return res.status(400).json({ error: "Invalid OTP" });
    }


    // Clear OTP after successful verification
    delete otpStore[email];


    // Check if email already exists
    const emailCheckQuery = "SELECT * FROM users WHERE email = ?";
    db.query(emailCheckQuery, [email], (emailErr, emailResult) => {
        if (emailErr) {
            return res.status(500).json({ error: "Error checking email existence" });
        }
        if (emailResult.length > 0) {
            return res.status(400).json({ error: "Email already in use" });
        }

        // Check if name already exists
        const nameCheckQuery = "SELECT * FROM users WHERE name = ?";
        db.query(nameCheckQuery, [name], (nameErr, nameResult) => {
            if (nameErr) {
                return res.status(500).json({ error: "Error checking name existence" });
            }
            if (nameResult.length > 0) {
                return res.status(400).json({ error: "User name already in use" });
            }

            bcrypt.hash(password.toString(), salt, (hashErr, hash) => {
                if (hashErr) {
                    console.log(hashErr)
                    return res.status(500).json({ error: "Error hashing password" });
                }

                const sql = "INSERT INTO users (`name`, `email`, `gender`, `city`, `password`, `profile_photo`) VALUES (?, ?, ?, ?, ?, ?)";
                const values = [name, email, gender, city, hash, profile_photo];
                db.query(sql, values, (insertErr, result) => {
                    if (insertErr) {
                        return res.status(500).json({ error: "Error inserting data into database" });
                    }
                    sendRegistrationSuccessByEmail(name, email)
                    return res.json({ status: "Success" });
                });
            });
        });
    });
});

// User Login Route
router.post('/login', (req, res) => {
    const sql = 'SELECT * FROM users WHERE email=?';
    db.query(sql, [req.body.email], (err, data) => {
        if (err) {
            return res.status(500).json({ error: "Login error in server" });
        } if (data.length > 0) {
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if (err) {
                    return res.status(500).json({ error: "Password hash error" });
                } if (response) {
                    const name = data[0].name;
                    const profile_photo = data[0].profile_photo
                    const user_token = jwt.sign({ name }, userTokenSecretKey, { expiresIn: '1d' });
                    // res.cookie('user_token', user_token);
                    res.cookie('user_token', user_token, {
                        httpOnly: true,  // Ensure the cookie is not accessible by JavaScript (for security)
                        secure: false,    // Use 'true' in production if you're using HTTPS
                        sameSite: 'None' // Required for cross-origin requests (especially if frontend/backend are on different domains)
                    });
                    return res.json({ status: "Success" });
                } else {
                    return res.status(500).json({ error: "Password not matched" });
                }
            })
        } else {
            return res.status(500).json({ error: "No email exists" });
        }
    })
});

router.post('/checkCredentials', (req, res) => {
    const { userId, password } = req.body;

    // Query to retrieve user data based on userId
    const getUserQuery = 'SELECT * FROM users WHERE user_id = ?';

    // Execute the query
    db.query(getUserQuery, [userId], (err, results) => {
        if (err) {
            console.error("Error checking credentials:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        // Check if user with the provided userId exists
        if (results.length === 0) {
            return res.status(404).json({ status: "Error", error: "User not found" });
        }

        // User found, compare passwords
        const user = results[0];
        bcrypt.compare(password.toString(), user.password, (compareErr, compareResult) => {
            if (compareErr) {
                console.error("Error comparing passwords:", compareErr);
                return res.status(500).json({ status: "Error", error: "Internal Server Error" });
            }

            // Passwords match
            if (compareResult) {
                return res.json({ status: "Success", message: "Valid credentials" });
            } else {
                return res.status(401).json({ status: "Error", error: "Password not matched" });
            }
        });
    });
});


const verifyUser = (req, res, next) => {
    const user_token = req.cookies.user_token;

    if (!user_token) {
        return res.json({ error: "You are not authenticated" });
    } else {
        jwt.verify(user_token, userTokenSecretKey, (err, decoded) => {
            if (err) {
                return res.json({ error: "Error in user token" });
            } else {
                req.name = decoded.name;

                // Retrieve user data including profile_photo
                const sql = 'SELECT name,user_id, profile_photo FROM users WHERE name=?';
                db.query(sql, [req.name], (err, data) => {
                    if (err) {
                        return res.status(500).json({ error: "Error retrieving user data" });
                    }
                    req.userData = data[0]; // Assuming there's only one user with this name
                    next();
                });
            }
        });
    }
};

// Protected Route for User
router.get('/', verifyUser, (req, res) => {
    if (req.userData.profile_photo) {
        return res.json({ status: "Success", user_id: req.userData.user_id, name: req.userData.name, profile_photo: (req.userData.profile_photo).toString() });
    }
    return res.json({ status: "Success", user_id: req.userData.user_id, name: req.userData.name, profile_photo: (req.userData.profile_photo) });
});

// User Logout Route
router.get('/logout', (req, res) => {
    res.clearCookie('user_token');
    return res.json({ status: "Success" });
});
router.get('/grounds', (req, res) => {
    const sql = `
    SELECT 
        g.ground_id, 
        g.type, 
        g.description,
        TIME_FORMAT(g.start_time, '%H:%i') AS start_time, 
        TIME_FORMAT(g.end_time, '%H:%i') AS end_time, 
        g.price, 
        c.name AS club_name,
        c.address,
        g.photo1,
        g.photo2,
        g.photo3,
        g.photo4,
        COUNT(CASE WHEN b.status='confirmed' THEN b.booking_id END) AS popularityCount
    FROM 
        grounds AS g
    INNER JOIN 
        clubs AS c ON g.club_id = c.club_id
    LEFT JOIN 
        bookings AS b ON g.ground_id = b.ground_id
    WHERE 
        g.visibility = 1
    GROUP BY 
        g.ground_id
    ORDER BY 
        popularityCount DESC`;

    db.query(sql, (err, results) => {
        if (err) {
            console.error("Error fetching ground data:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        const grounds = results.map(ground => ({
            ...ground,
            photo1: ground.photo1 ? ground.photo1.toString() : null,
            photo2: ground.photo2 ? ground.photo2.toString() : null,
            photo3: ground.photo3 ? ground.photo3.toString() : null,
            photo4: ground.photo4 ? ground.photo4.toString() : null,
            popular: false // Initialize popular flag for each ground
        }));

        // Mark top 3 grounds as popular
        grounds.slice(0, 3).forEach(ground => {
            ground.popular = true;
        });

        res.json({ status: "Success", grounds });
    });
});


router.get('/activities', (req, res) => {
    const currentDate = new Date().toISOString().split('T')[0]; // Get current date in YYYY-MM-DD format

    const sql = `SELECT 
        a.activity_id, 
        a.activity_name, 
        a.category,
        a.description,
        a.age_group,
        DATE_FORMAT(a.start_date, '%Y-%m-%d') AS start_date,
        DATE_FORMAT(a.end_date, '%Y-%m-%d') AS end_date,
        TIME_FORMAT(a.start_time, '%H:%i') AS start_time, 
        TIME_FORMAT(a.end_time, '%H:%i') AS end_time, 
        a.instructor_info,
        a.capacity,
        a.price, 
        c.name AS club_name,
        c.address,
        a.photo1,
        a.photo2,
        a.photo3,
        a.photo4,
        a.contact_information
    FROM activities AS a
    INNER JOIN clubs AS c ON a.club_id = c.club_id
    WHERE a.end_date > '${currentDate}' AND a.visibility = 1`; // Filter activities with end date later than today

    db.query(sql, (err, results) => {
        if (err) {
            console.error("Error fetching activity data:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        const activitiesWithPhotos = results.map(activity => ({
            ...activity,
            photo1: activity.photo1 ? activity.photo1.toString() : null,
            photo2: activity.photo2 ? activity.photo2.toString() : null,
            photo3: activity.photo3 ? activity.photo3.toString() : null,
            photo4: activity.photo4 ? activity.photo4.toString() : null
        }));

        res.json({ status: "Success", activities: activitiesWithPhotos });
    });
});

router.get('/grounds/:groundId', (req, res) => {
    const groundId = req.params.groundId;

    const sql = `SELECT 
    g.ground_id, 
    g.type, 
    g.description,
    TIME_FORMAT(g.start_time, '%H:%i') AS start_time, 
    TIME_FORMAT(g.end_time, '%H:%i') AS end_time, 
    g.price, 
    c.name AS club_name,
    c.description AS club_description,
    c.address,
    g.photo1,
    g.photo2,
    g.photo3,
    g.photo4
FROM grounds AS g
INNER JOIN clubs AS c ON g.club_id = c.club_id
    WHERE g.ground_id = ?`;

    db.query(sql, [groundId], (err, results) => {
        if (err) {
            console.error("Error fetching ground data:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: "Error", error: "Ground not found" });
        }

        const ground = results[0];

        // Convert photo paths to strings
        const groundWithPhotos = {
            ...ground,
            photo1: ground.photo1 ? ground.photo1.toString() : null,
            photo2: ground.photo2 ? ground.photo2.toString() : null,
            photo3: ground.photo3 ? ground.photo3.toString() : null,
            photo4: ground.photo4 ? ground.photo4.toString() : null
        };

        res.json({ status: "Success", ground: groundWithPhotos });
    });
});

router.get('/activities/:activityId', (req, res) => {
    const activityId = req.params.activityId;

    const sql = `SELECT 
        a.activity_id,
        a.activity_name,
        a.category,
        a.description AS activity_description,
        a.age_group,
        DATE_FORMAT(a.start_date, '%Y-%m-%d') AS start_date,
        DATE_FORMAT(a.end_date, '%Y-%m-%d') AS end_date,
        TIME_FORMAT(a.start_time, '%H:%i') AS start_time,
        TIME_FORMAT(a.end_time, '%H:%i') AS end_time,
        a.instructor_info,
        a.capacity,
        a.price,
        a.contact_information,
        a.photo1,
        a.photo2,
        a.photo3,
        a.photo4,
        c.name AS club_name,
        c.address,
        c.description AS club_description
    FROM activities AS a
    INNER JOIN clubs AS c ON a.club_id = c.club_id
    WHERE a.activity_id = ?`;

    db.query(sql, [activityId], (err, results) => {
        if (err) {
            console.error("Error fetching activity data:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: "Error", error: "Activity not found" });
        }

        const activity = results[0];

        // Convert photo paths to strings if they exist
        const activityWithPhotos = {
            ...activity,
            photo1: activity.photo1 ? activity.photo1.toString() : null,
            photo2: activity.photo2 ? activity.photo2.toString() : null,
            photo3: activity.photo3 ? activity.photo3.toString() : null,
            photo4: activity.photo4 ? activity.photo4.toString() : null
        };

        res.json({ status: "Success", activity: activityWithPhotos });
    });
});

const checkUserBalance = (userId, amount, callback) => {
    const getUserBalanceQuery = `
        SELECT balance FROM user_wallet
        WHERE user_id = ?`;
    db.query(getUserBalanceQuery, [userId], (error, result) => {
        if (error) {
            console.error("Error checking user balance:", error);
            return callback(error, null);
        }
        const userBalance = result[0].balance;
        if (userBalance >= amount) {
            callback(null, true); // Sufficient balance
        } else {
            callback(null, false); // Insufficient balance
        }
    });
};
// Function to update user wallet
const updateUserWallet = (userId, amount, callback) => {
    const updateUserWalletQuery = `
        UPDATE user_wallet
        SET balance = balance - ?
        WHERE user_id = ?`;
    db.query(updateUserWalletQuery, [amount, userId], (error, result) => {
        if (error) {
            console.error("Error updating user wallet:", error);
            return callback(error, null);
        }
        callback(null, result);
    });
};

// Function to update club wallet
const updateClubWallet = (groundId, amount, callback) => {
    const updateClubWalletQuery = `
        UPDATE club_wallet
        SET balance = balance + ?
        WHERE club_id = (SELECT club_id FROM grounds WHERE ground_id = ?)`;
    db.query(updateClubWalletQuery, [amount, groundId], (error, result) => {
        if (error) {
            console.error("Error updating club wallet:", error);
            return callback(error, null);
        }
        callback(null, result);
    });
};

const refundUserWallet = (userId, amount, callback) => {
    console.log("User " + amount)
    const updateUserWalletQuery = `
        UPDATE user_wallet
        SET balance = balance + ?
        WHERE user_id = ?`;
    db.query(updateUserWalletQuery, [amount, userId], (error, result) => {
        if (error) {
            console.error("Error updating user wallet:", error);
            return callback(error, null);
        }
        callback(null, result);
    });
};

const refundClubWallet = (groundId, amount, callback) => {
    console.log("Club " + amount)
    const updateClubWalletQuery = `
        UPDATE club_wallet
        SET balance = balance - ?
        WHERE club_id = (SELECT club_id FROM grounds WHERE ground_id = ?)`;
    db.query(updateClubWalletQuery, [amount, groundId], (error, result) => {
        if (error) {
            console.error("Error updating club wallet:", error);
            return callback(error, null);
        }
        callback(null, result);
    });
};

const addTransaction = (transactionType, operation, amount, club_id, user_id, relatedType, callback) => {
    const addTransactionQuery = `
        INSERT INTO wallet_transactions 
        (transaction_type, operation, amount, club_id, user_id,related_type) 
        VALUES (?, ?, ?, ?, ?, ?)`;
    db.query(addTransactionQuery, [transactionType, operation, amount, club_id, user_id, relatedType], (error, result) => {
        if (error) {
            console.error("Error adding transaction:", error);
            return callback(error, null);
        }
        callback(null, result);
    });
};


// Assuming addTransaction function is imported or defined here

router.post('/grounds/:groundId/book', (req, res) => {
    const { groundId } = req.params;
    const { userId, date, startTime, endTime, amount } = req.body;

    // Get current time
    const currentTime = new Date().toISOString().split('T')[1].split('.')[0];

    // Check if the booking start time is in the future
    if (date === new Date().toISOString().split('T')[0] && startTime < currentTime) {
        return res.status(400).json({ status: "Error", error: "Cannot book past time slots for today" });
    }

    // Check user balance before proceeding with booking
    checkUserBalance(userId, amount, (checkUserBalanceErr, sufficientBalance) => {
        if (checkUserBalanceErr) {
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        if (!sufficientBalance) {
            return res.status(400).json({ status: "Error", error: "Insufficient balance in your wallet" });
        }

        // Begin a database transaction
        db.beginTransaction(function (err) {
            if (err) {
                console.error("Error beginning transaction:", err);
                return res.status(500).json({ status: "Error", error: "Internal Server Error" });
            }

            // Fetch clubId using groundId
            const fetchClubIdQuery = `SELECT club_id FROM grounds WHERE ground_id = ?`;
            db.query(fetchClubIdQuery, [groundId], (fetchClubIdErr, fetchClubIdResult) => {
                if (fetchClubIdErr) {
                    console.error("Error fetching clubId:", fetchClubIdErr);
                    return db.rollback(function () {
                        res.status(500).json({ status: "Error", error: "Internal Server Error" });
                    });
                }

                const clubId = fetchClubIdResult[0].club_id;

                // Check if the slot spans across two different dates
                let adjustedEndTime = endTime;
                if (startTime > endTime) {
                    adjustedEndTime = '23:59:59'; // End time for the current date
                }

                // Check if the requested time slot is available
                const availabilityQuery = `SELECT * FROM bookings 
                                           WHERE ground_id = ? 
                                           AND date = ? 
                                           AND status='confirmed'
                                           AND ((booking_start_time < ? AND booking_end_time > ?) 
                                                OR (booking_start_time < ? AND booking_end_time > ?) 
                                                OR (booking_start_time >= ? AND booking_end_time <= ?)) FOR UPDATE`;

                db.query(availabilityQuery, [groundId, date, startTime, adjustedEndTime, startTime, adjustedEndTime, startTime, adjustedEndTime], (availabilityErr, availabilityResult) => {
                    if (availabilityErr) {
                        console.error("Error checking availability:", availabilityErr);
                        return db.rollback(function () {
                            res.status(500).json({ status: "Error", error: "Internal Server Error" });
                        });
                    }

                    // If there are overlapping bookings, rollback transaction and return "Slot not available"
                    if (availabilityResult.length > 0) {
                        // If there are overlapping bookings, send response and return to exit the function
                        return res.status(400).json({ error: "No slots available for specified time" });
                    }

                    // If the slot is available, insert a new booking record
                    const insertQuery = `INSERT INTO bookings (ground_id, user_id, date, booking_start_time, booking_end_time) 
                                         VALUES (?, ?, ?, ?, ?)`;

                    db.query(insertQuery, [groundId, userId, date, startTime, endTime], (insertErr, insertResult) => {
                        if (insertErr) {
                            console.error("Error booking ground slot:", insertErr);
                            return db.rollback(function () {
                                res.status(500).json({ error: "Internal Server Error" });
                            });
                        }

                        // Update User Wallet
                        updateUserWallet(userId, amount, (updateUserWalletErr, updateUserWalletResult) => {
                            if (updateUserWalletErr) {
                                return db.rollback(function () {
                                    res.status(500).json({ error: "Internal Server Error" });
                                });
                            }

                            // Add transaction record for User Wallet
                            const userTransactionType = 'debit';
                            const userOperation = 'booking';
                            const userRelatedType = 'user';

                            addTransaction(userTransactionType, userOperation, amount, clubId, userId, userRelatedType, (userTransactionErr, userTransactionResult) => {
                                if (userTransactionErr) {
                                    return db.rollback(function () {
                                        res.status(500).json({ error: "Internal Server Error" });
                                    });
                                }

                                // Update Club Wallet
                                updateClubWallet(groundId, amount, (updateClubWalletErr, updateClubWalletResult) => {
                                    if (updateClubWalletErr) {
                                        // Since the booking was successful but there was an error updating club wallet,
                                        // consider rolling back the user wallet update or handling this scenario appropriately
                                        return db.rollback(function () {
                                            res.status(500).json({ error: "Internal Server Error" });
                                        });
                                    }

                                    // Add transaction record for Club Wallet
                                    const clubTransactionType = 'credit';
                                    const clubOperation = 'booking';
                                    const clubRelatedType = 'club';

                                    addTransaction(clubTransactionType, clubOperation, amount, clubId, userId, clubRelatedType, (clubTransactionErr, clubTransactionResult) => {
                                        if (clubTransactionErr) {
                                            return db.rollback(function () {
                                                res.status(500).json({ error: "Internal Server Error" });
                                            });
                                        }

                                        // Commit transaction if everything is successful
                                        db.commit(function (commitErr) {
                                            if (commitErr) {
                                                console.error("Error committing transaction:", commitErr);
                                                return db.rollback(function () {
                                                    res.status(500).json({ error: "Internal Server Error" });
                                                });
                                            }
                                            return res.json({ status: "Success", message: "Ground slot booked successfully" });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});




// User Cancel Booking Route
// Assuming addTransaction function is imported or defined here

router.post('/bookings/:bookingId/cancel', verifyUser, (req, res) => {
    const bookingId = req.params.bookingId;
    const userId = req.userData.user_id;
    const groundId = req.body.ground_id;
    const refundAmount = req.body.amount;
    const bookingDate = moment(req.body.booking_date);
    const bookingStartTime = moment(req.body.booking_start_time, "HH:mm:ss");
    const currentDate = moment();
    const combinedDateTime = moment({
        year: bookingDate.year(),
        month: bookingDate.month(),
        date: bookingDate.date(),
        hour: bookingStartTime.hour(),
        minute: bookingStartTime.minute(),
        second: bookingStartTime.second()
    });

    const hoursDifference = Math.abs(currentDate.diff(combinedDateTime, 'hours'));

    console.log("Difference in hours:", hoursDifference);
    let refundPercentage;

    // Determine refund percentage based on hoursDifference
    if (hoursDifference >= 24) {
        refundPercentage = 1; // 100%
    } else if (hoursDifference < 24 && hoursDifference > 12) {
        refundPercentage = 0.75; // 75%
    } else if (hoursDifference <= 12 && hoursDifference > 6) {
        refundPercentage = 0.5; // 50%
    } else if (hoursDifference <= 6) {
        refundPercentage = 0.25; // 25%
    }

    // Calculate the refund amount
    const actualRefundAmount = refundAmount * refundPercentage;
    // Fetch clubId using groundId
    const fetchClubIdQuery = `SELECT club_id FROM grounds WHERE ground_id = ?`;
    db.query(fetchClubIdQuery, [groundId], (fetchClubIdErr, fetchClubIdResult) => {
        if (fetchClubIdErr) {
            console.error("Error fetching clubId:", fetchClubIdErr);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        const clubId = fetchClubIdResult[0].club_id;

        // Check if the booking belongs to the user
        const checkOwnershipQuery = 'SELECT * FROM bookings WHERE booking_id = ? AND user_id = ?';
        db.query(checkOwnershipQuery, [bookingId, userId], (checkErr, checkResults) => {
            if (checkErr) {
                console.error("Error checking ownership:", checkErr);
                return res.status(500).json({ status: "Error", error: "Internal Server Error" });
            }

            if (checkResults.length === 0) {
                return res.status(403).json({ status: "Error", error: "You are not authorized to cancel this booking" });
            }

            // Begin a database transaction
            db.beginTransaction(function (cancelErr) {
                if (cancelErr) {
                    console.error("Error beginning transaction:", cancelErr);
                    return res.status(500).json({ status: "Error", error: "Internal Server Error" });
                }

                // Refund the amount to the user
                refundUserWallet(userId, actualRefundAmount, (updateUserWalletErr) => {
                    if (updateUserWalletErr) {
                        return db.rollback(function () {
                            res.status(500).json({ status: "Error", error: "Internal Server Error" });
                        });
                    }

                    // Update club wallet (if needed)
                    // Ensure to pass correct parameters to updateClubWallet function
                    refundClubWallet(groundId, actualRefundAmount, (updateClubWalletErr) => {
                        if (updateClubWalletErr) {
                            // Rollback transaction if club wallet update fails
                            return db.rollback(function () {
                                res.status(500).json({ status: "Error", error: "Internal Server Error" });
                            });
                        }

                        // Delete the booking record
                        const cancelQuery = `UPDATE bookings SET status = 'cancelled' WHERE booking_id = ?`;

                        db.query(cancelQuery, [bookingId], (cancelErr, cancelResults) => {
                            if (cancelErr) {
                                console.error("Error canceling booking:", cancelErr);
                                return db.rollback(function () {
                                    res.status(500).json({ status: "Error", error: "Internal Server Error" });
                                });
                            }

                            // Add transaction record for User Wallet
                            const userTransactionType = 'credit';
                            const userOperation = 'cancellation';
                            const userRelatedType = 'user';

                            addTransaction(userTransactionType, userOperation, actualRefundAmount, clubId, userId, userRelatedType, (userTransactionErr, userTransactionResult) => {
                                if (userTransactionErr) {
                                    return db.rollback(function () {
                                        res.status(500).json({ status: "Error", error: "Internal Server Error" });
                                    });
                                }

                                // Add transaction record for Club Wallet
                                const clubTransactionType = 'debit';
                                const clubOperation = 'cancellation';
                                const clubRelatedType = 'club';

                                addTransaction(clubTransactionType, clubOperation, actualRefundAmount, clubId, userId, clubRelatedType, (clubTransactionErr, clubTransactionResult) => {
                                    if (clubTransactionErr) {
                                        return db.rollback(function () {
                                            res.status(500).json({ status: "Error", error: "Internal Server Error" });
                                        });
                                    }

                                    // Commit transaction if everything is successful
                                    db.commit(function (commitErr) {
                                        if (commitErr) {
                                            console.error("Error committing transaction:", commitErr);
                                            return db.rollback(function () {
                                                res.status(500).json({ status: "Error", error: "Internal Server Error" });
                                            });
                                        }
                                        return res.json({ status: "Success", message: "Booking cancelled successfully. Refunded amount: ₹" + actualRefundAmount });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});



router.get('/wallet/balance', verifyUser, (req, res) => {
    const userId = req.userData.user_id;

    // Query to retrieve wallet balance for the user
    const getBalanceQuery = 'SELECT balance FROM user_wallet WHERE user_id = ?';

    // Execute the query
    db.query(getBalanceQuery, [userId], (err, results) => {
        if (err) {
            console.error("Error fetching wallet balance:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        if (results.length === 0) {
            // If no wallet record exists, create one with initial balance 0
            const createWalletQuery = 'INSERT INTO user_wallet (user_id, balance) VALUES (?, 0)';
            db.query(createWalletQuery, [userId], (createErr, createResult) => {
                if (createErr) {
                    console.error("Error creating wallet:", createErr);
                    return res.status(500).json({ status: "Error", error: "Internal Server Error" });
                }

                res.json({ status: "Success", balance: 0 });
            });
        } else {
            // Wallet record exists, return the balance
            const balance = results[0].balance;
            res.json({ status: "Success", balance });
        }
    });
});

// Assuming addTransaction function is imported or defined here

router.post('/wallet/add', verifyUser, (req, res) => {
    const userId = req.userData.user_id;
    const { amount } = req.body;

    // Validate amount
    if (!amount || isNaN(amount) || amount <= 0) {
        return res.status(400).json({ status: "Error", error: "Invalid amount" });
    }

    // Query to retrieve the current wallet balance
    const getBalanceQuery = 'SELECT balance FROM user_wallet WHERE user_id = ?';

    // Execute the query to get the current balance
    db.query(getBalanceQuery, [userId], (balanceErr, balanceResults) => {
        if (balanceErr) {
            console.error("Error fetching wallet balance:", balanceErr);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        // Check if balance results are available and contain a valid balance
        if (!balanceResults || !balanceResults[0] || isNaN(balanceResults[0].balance)) {
            return res.status(500).json({ status: "Error", error: "Invalid wallet balance data" });
        }

        // Retrieve the current balance
        const currentBalance = parseFloat(balanceResults[0].balance);

        // Check if current balance is a valid number
        if (isNaN(currentBalance)) {
            return res.status(500).json({ status: "Error", error: "Invalid wallet balance data" });
        }

        // Calculate the new balance after adding the amount
        const newBalance = currentBalance + parseFloat(amount);

        // Check if the new balance would exceed the limit of 10000
        if (newBalance > 10000) {
            return res.status(400).json({ status: "Error", error: "The maximum limit for your wallet balance is 10,000." });
        }

        // Begin a database transaction
        db.beginTransaction(function (err) {
            if (err) {
                console.error("Error beginning transaction:", err);
                return res.status(500).json({ status: "Error", error: "Internal Server Error" });
            }

            // Query to add amount to user's wallet
            const addAmountQuery = 'UPDATE user_wallet SET balance = balance + ? WHERE user_id = ?';

            // Execute the query to add the amount to the wallet
            db.query(addAmountQuery, [amount, userId], (addErr, addResults) => {
                if (addErr) {
                    console.error("Error adding amount to wallet:", addErr);
                    return db.rollback(function () {
                        res.status(500).json({ status: "Error", error: "Internal Server Error" });
                    });
                }

                // Add transaction record for wallet addition
                const transactionType = 'credit';
                const operation = 'recharge';
                const related_type = 'user';

                addTransaction(transactionType, operation, amount, null, userId, related_type, (transactionErr, transactionResult) => {
                    if (transactionErr) {
                        return db.rollback(function () {
                            res.status(500).json({ status: "Error", error: "Internal Server Error" });
                        });
                    }

                    // Commit transaction if everything is successful
                    db.commit(function (commitErr) {
                        if (commitErr) {
                            console.error("Error committing transaction:", commitErr);
                            return db.rollback(function () {
                                res.status(500).json({ status: "Error", error: "Internal Server Error" });
                            });
                        }
                        return res.json({ status: "Success", message: "Amount added to wallet successfully" });
                    });
                });
            });
        });
    });
});

router.get('/transactions', verifyUser, (req, res) => {
    const userId = req.userData.user_id;

    // Query to retrieve transactions along with operation and club name
    const getTransactionsQuery = `
        SELECT wt.transaction_id, wt.transaction_type, wt.operation, wt.amount, wt.transaction_time, wt.related_type, 
               c.name AS club_name
        FROM wallet_transactions wt
        LEFT JOIN clubs c ON wt.club_id = c.club_id
        WHERE wt.user_id = ? AND wt.related_type='user'`;

    // Execute the query
    db.query(getTransactionsQuery, [userId], (err, results) => {
        if (err) {
            console.error("Error fetching transactions:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        // Send the retrieved transactions data as JSON response
        res.json({ status: "Success", transactions: results });
    });
});



router.get('/grounds/:groundId/bookings', (req, res) => {
    const groundId = req.params.groundId;
    const date = req.query.date;

    const sql = `SELECT * FROM bookings WHERE ground_id = ? AND date = ? AND status='confirmed'`;

    db.query(sql, [groundId, date], (err, results) => {
        if (err) {
            console.error("Error fetching bookings:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        res.json({ status: "Success", bookings: results });
    });
});

router.get('/getBookings', verifyUser, (req, res) => {
    const user_id = req.userData.user_id;
    const currentDate = new Date().toISOString().split('T')[0]; // Get current date in YYYY-MM-DD format

    const sql = `SELECT b.booking_id, DATE_FORMAT(b.date, '%Y-%m-%d') AS date, b.booking_start_time, b.booking_end_time, b.status,g.club_id, g.ground_id, g.type AS ground_type, c.name AS club_name
                 FROM bookings AS b
                 INNER JOIN grounds AS g ON b.ground_id = g.ground_id
                 INNER JOIN clubs AS c ON g.club_id = c.club_id
                 WHERE b.user_id = ? `;

    db.query(sql, [user_id, currentDate], (err, results) => {
        if (err) {
            console.error("Error fetching bookings:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        res.json({ status: "Success", bookings: results });
    });
});
// User Cancel Booking Route
router.get('/bookings/:bookingId', verifyUser, (req, res) => {
    const bookingId = req.params.bookingId;
    const userId = req.userData.user_id;

    // Query to fetch details of the booking along with ground and club details
    const sql = `SELECT b.*, 
                        g.ground_id, 
                        g.type AS ground_type, 
                        g.description AS ground_description,
                        g.start_time AS ground_start_time,
                        g.end_time AS ground_end_time,
                        g.price AS ground_price,
                        c.club_id,
                        c.name AS club_name,
                        c.address AS club_address
                 FROM bookings AS b
                 INNER JOIN grounds AS g ON b.ground_id = g.ground_id
                 INNER JOIN clubs AS c ON g.club_id = c.club_id
                 WHERE b.booking_id = ? AND b.user_id = ?`;

    // Execute the query
    db.query(sql, [bookingId, userId], (err, results) => {
        if (err) {
            console.error("Error fetching booking details:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: "Error", error: "Booking not found" });
        }

        const booking = results[0];

        // Calculate duration
        const startTime = new Date(`1970-01-01T${booking.booking_start_time}`);
        const endTime = new Date(`1970-01-01T${booking.booking_end_time}`);
        const durationMilliseconds = endTime - startTime;
        const durationHours = Math.floor(durationMilliseconds / (1000 * 60 * 60));
        const durationMinutes = Math.floor((durationMilliseconds % (1000 * 60 * 60)) / (1000 * 60));

        const duration = `${durationHours} hours ${durationMinutes} minutes`;

        // Add duration to the booking object
        booking.duration = duration;

        return res.json({ status: "Success", booking });
    });
});

router.post('/updateProfile', verifyUser, upload.single('profile_photo'), (req, res) => {
    const userId = req.userData.user_id;
    const { name, email } = req.body;
    let profile_photo = null;
    if (req.body.profile_photo != null) {
        profile_photo = req.body.profile_photo;
    }

    // Check if the provided email is already in use by another user
    if (email) {
        const emailCheckQuery = "SELECT * FROM users WHERE email = ? AND user_id != ?";
        db.query(emailCheckQuery, [email, userId], (emailErr, emailResult) => {
            if (emailErr) {
                return res.status(500).json({ error: "Error checking email existence" });
            }
            if (emailResult.length > 0) {
                return res.status(400).json({ error: "Email already in use" });
            }

            // Update email if available
            const updateEmailQuery = "UPDATE users SET email = ? WHERE user_id = ?";
            db.query(updateEmailQuery, [email, userId], (updateEmailErr, updateEmailResult) => {
                if (updateEmailErr) {
                    return res.status(500).json({ error: "Error updating email" });
                }
                // If name is also provided, update it as well
                if (name) {
                    updateName(name, userId, profile_photo, res);
                } else {
                    return res.json({ status: "Success", message: "Email updated successfully" });
                }
            });
        });
    } else if (name) {
        // If only name is provided, update name
        updateName(name, userId, profile_photo, res);
    } else if (profile_photo) {
        // If only profile photo is provided, update profile photo
        const updateProfilePhotoQuery = "UPDATE users SET profile_photo = ? WHERE user_id = ?";
        db.query(updateProfilePhotoQuery, [profile_photo, userId], (updatePhotoErr, updatePhotoResult) => {
            if (updatePhotoErr) {
                return res.status(500).json({ error: "Error updating profile photo" });
            }
            return res.json({ status: "Success", message: "Profile photo updated successfully" });
        });
    } else {
        return res.status(400).json({ error: "No data provided for update" });
    }
});

// Function to update name
function updateName(name, userId, profile_photo, res) {
    const nameCheckQuery = "SELECT * FROM users WHERE name = ? AND user_id != ?";
    db.query(nameCheckQuery, [name, userId], (nameErr, nameResult) => {
        if (nameErr) {
            return res.status(500).json({ error: "Error checking name existence" });
        }
        if (nameResult.length > 0) {
            return res.status(400).json({ error: "User name already in use" });
        }

        const updateNameQuery = "UPDATE users SET name = ? WHERE user_id = ?";
        db.query(updateNameQuery, [name, userId], (updateNameErr, updateNameResult) => {
            if (updateNameErr) {
                return res.status(500).json({ error: "Error updating name" });
            }
            if (profile_photo) {
                // If profile photo is also provided, update it
                const updateProfilePhotoQuery = "UPDATE users SET profile_photo = ? WHERE user_id = ?";
                db.query(updateProfilePhotoQuery, [profile_photo, userId], (updatePhotoErr, updatePhotoResult) => {
                    if (updatePhotoErr) {
                        return res.status(500).json({ error: "Error updating profile photo" });
                    }
                    return res.json({ status: "Success", message: "Name and profile photo updated successfully" });
                });
            } else {
                return res.json({ status: "Success", message: "Name updated successfully" });
            }
        });
    });
}

// Activity Enquiry Route
router.post('/activities/:activityId/enquiry', verifyUser, (req, res) => {
    const { activityId } = req.params;
    const userId = req.userData.user_id;
    const { inquiry_message } = req.body;
    const { contact_info } = req.body;

    // Validate required fields
    if (!inquiry_message || !contact_info) {
        return res.status(400).json({ error: "Contact information and question are required" });
    }

    // Store the activity enquiry in the database
    const insertEnquiryQuery = 'INSERT INTO activity_inquiries (activity_id, user_id,inquiry_message,contact_info) VALUES (?, ?, ?,?)';
    db.query(insertEnquiryQuery, [activityId, userId, inquiry_message, contact_info], (err, result) => {
        if (err) {
            console.error("Error storing activity enquiry:", err);
            return res.status(500).json({ error: "Internal Server Error" });
        }
        return res.json({ status: "Success", message: "Activity enquiry submitted successfully" });
    });
});


router.get('/stats', verifyUser, (req, res) => {
    const userId = req.userData.user_id;
    const { timePeriod } = req.query; // Retrieve timePeriod from query parameters

    // Ensure timePeriod is provided
    if (!timePeriod) {
        return res.status(400).json({ status: 'Error', error: 'Time period is required' });
    }

    let startDate;
    switch (timePeriod) {
        case '1week':
            startDate = moment().subtract(1, 'weeks').format('YYYY-MM-DD');
            break;
        case '1month':
            startDate = moment().subtract(1, 'months').format('YYYY-MM-DD');
            break;
        case '3months':
            startDate = moment().subtract(3, 'months').format('YYYY-MM-DD');
            break;
        case '6months':
            startDate = moment().subtract(6, 'months').format('YYYY-MM-DD');
            break;
        case '1year':
            startDate = moment().subtract(1, 'years').format('YYYY-MM-DD');
            break;
        default:
            return res.status(400).json({ status: 'Error', error: 'Invalid time period' });
    }

    // SQL queries to fetch user statistics based on the selected time period
    const sqlTotalConfirmedBookings = `
        SELECT COUNT(*) AS totalConfirmedBookings
        FROM bookings
        WHERE user_id = ? AND status = 'confirmed' AND date >= ?;
    `;

    const sqlTotalCancelledBookings = `
        SELECT COUNT(*) AS totalCancelledBookings
        FROM bookings
        WHERE user_id = ? AND status = 'cancelled' AND date >= ?;
    `;

    const sqlTotalSlotsSpent = `
        SELECT SUM(TIMESTAMPDIFF(HOUR, booking_start_time, booking_end_time)) AS totalSlotsSpent
        FROM bookings
        WHERE user_id = ? AND date >= ? AND status='confirmed';
    `;

    const sqlTotalAmountSpent = `
    SELECT SUM(TIMESTAMPDIFF(HOUR, booking_start_time, booking_end_time) * price) AS totalAmountSpent
    FROM bookings
    INNER JOIN grounds ON bookings.ground_id = grounds.ground_id
    WHERE user_id = ? AND date >= ?
    AND status = 'confirmed'; 
`;



    const sqlFavouriteGroundType = `
    SELECT g.type
    FROM grounds g
    JOIN (
        SELECT ground_id, COUNT(*) AS booking_count
        FROM bookings
        WHERE user_id = ?
        GROUP BY ground_id
        ORDER BY booking_count DESC
        LIMIT 1
    ) AS b ON g.ground_id = b.ground_id;
`;


    const sqlFavouriteClub = `
    SELECT c.name AS favouriteClub
    FROM clubs c
    JOIN (
        SELECT club_id, COUNT(*) AS booking_count
        FROM bookings
        INNER JOIN grounds ON bookings.ground_id = grounds.ground_id
        WHERE user_id = ?
        GROUP BY club_id
        ORDER BY booking_count DESC
        LIMIT 1
    ) AS b ON c.club_id = b.club_id;
`;

    const sqlFavouriteTimeSlot = `
    SELECT TIME(booking_start_time) AS favouriteTimeSlot
    FROM bookings
    WHERE user_id = ?
    GROUP BY TIME(booking_start_time)
    ORDER BY COUNT(*) DESC
    LIMIT 1;
`;




    // Execute all SQL queries
    db.query(sqlTotalConfirmedBookings, [userId, startDate], (err, results1) => {
        if (err) {
            console.error("Error fetching total confirmed bookings:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        db.query(sqlTotalCancelledBookings, [userId, startDate], (err, results2) => {
            if (err) {
                console.error("Error fetching total cancelled bookings:", err);
                return res.status(500).json({ status: "Error", error: "Internal Server Error" });
            }

            db.query(sqlTotalSlotsSpent, [userId, startDate], (err, results3) => {
                if (err) {
                    console.error("Error fetching total slots spent:", err);
                    return res.status(500).json({ status: "Error", error: "Internal Server Error" });
                }

                db.query(sqlTotalAmountSpent, [userId, startDate], (err, results4) => {
                    if (err) {
                        console.error("Error fetching total amount spent:", err);
                        return res.status(500).json({ status: "Error", error: "Internal Server Error" });
                    }

                    db.query(sqlFavouriteGroundType, [userId], (err, results5) => {
                        if (err) {
                            console.error("Error fetching favourite ground type:", err);
                            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
                        }

                        db.query(sqlFavouriteClub, [userId], (err, results6) => {
                            if (err) {
                                console.error("Error fetching favourite club:", err);
                                return res.status(500).json({ status: "Error", error: "Internal Server Error" });
                            }

                            db.query(sqlFavouriteTimeSlot, [userId], (err, results7) => {
                                if (err) {
                                    console.error("Error fetching favourite time slot:", err);
                                    return res.status(500).json({ status: "Error", error: "Internal Server Error" });
                                }

                                // Combine all results and send response
                                const statistics = {
                                    totalConfirmedBookings: results1[0].totalConfirmedBookings,
                                    totalCancelledBookings: results2[0].totalCancelledBookings,
                                    totalSlotsSpent: results3[0].totalSlotsSpent,
                                    totalAmountSpent: results4[0].totalAmountSpent,
                                    favouriteGroundType: results5.length ? results5[0].type : null,
                                    favouriteClub: results6.length ? results6[0].favouriteClub : null,
                                    favouriteTimeSlot: results7.length ? results7[0].favouriteTimeSlot : null
                                };
                                res.json({ status: "Success", statistics });
                            });
                        });
                    });
                });
            });
        });
    });
});





module.exports = router;
