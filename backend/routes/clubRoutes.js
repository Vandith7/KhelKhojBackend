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
const clubTokenSecretKey = process.env.CLUB_JWT_KEY;

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/'); // Save uploaded files to the 'uploads' directory
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname)); // Rename file to prevent name conflicts
    }
});

// Initialize multer upload middleware
const upload = multer({
    storage: storage
    , limits: {
        fieldNameSize: 1000 * 1024 * 1024,
        fieldSize: 1000 * 1024 * 1024
    }
});

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
                <p style="font-size: 16px; margin-top: 20px;">Your OTP for resetting your Khel-Khoj club account password is: <strong>${otp}</strong></p>
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
        subject: "Khel-Khoj Club Account Password Change Successful",
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
                <p style="font-size: 16px; margin-top: 20px;">Your Khel-Khoj club account password has been successfully changed.</p>
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
    const checkEmailQuery = "SELECT * FROM clubs WHERE email = ?";
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

    const getNameQuery = "SELECT name FROM clubs WHERE email = ?";
    db.query(getNameQuery, [email], (nameErr, nameResult) => {
        if (nameErr || nameResult.length === 0) {
            return res.status(500).json({ error: "Error fetching club's name" });
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
            const updatePasswordQuery = "UPDATE clubs SET password = ? WHERE email = ?";
            db.query(updatePasswordQuery, [hash, email], (updateErr, result) => {
                if (updateErr) {
                    return res.status(500).json({ error: "Error updating password" });
                }
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
                <p style="font-size: 16px;">Your OTP for club registration with Khel-Khoj is: <strong>${otp}</strong></p>
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
                <h2 style="text-align: center;">Club Registration Successful</h2>
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
    const checkQuery = "SELECT * FROM clubs WHERE email = ? OR name = ?";
    db.query(checkQuery, [email, name], (err, results) => {
        if (err) {
            return res.status(500).json({ error: "Error checking existence" });
        }

        for (let i = 0; i < results.length; i++) {
            if (results[i].email === email) {
                return res.status(400).json({ error: "Email already in use" });
            }
            if (results[i].name === name) {
                return res.status(400).json({ error: "Club name already in use, You may want to consider appending your city name to make it unique." });
            }
        }

        // Generate OTP with only numbers
        const otp = otpGenerator.generate(6, { upperCaseAlphabets: false, specialChars: false, lowerCaseAlphabets: false });
        otpStore[email] = otp;
        sendOTPByEmail(email, name, otp);
        res.json({ status: "OTP sent successfully" });
    });
});


// Club Register Route
router.post('/register', upload.single('profile_photo'), (req, res) => {
    const { name, email, password, address, description, otp } = req.body;
    const profile_photo = req.body.profile_photo;

    if (!otpStore[email] || otpStore[email] !== otp) {
        return res.status(400).json({ error: "Invalid OTP" });
    }

    // Clear OTP after successful verification
    delete otpStore[email];

    // Check if email already exists
    const emailCheckQuery = "SELECT * FROM clubs WHERE email = ?";
    db.query(emailCheckQuery, [email], (emailErr, emailResult) => {
        if (emailErr) {
            return res.status(500).json({ error: "Error checking email existence" });
        }
        if (emailResult.length > 0) {
            return res.status(400).json({ error: "Email already in use" });
        }

        // Check if name already exists
        const nameCheckQuery = "SELECT * FROM clubs WHERE name = ?";
        db.query(nameCheckQuery, [name], (nameErr, nameResult) => {
            if (nameErr) {
                return res.status(500).json({ error: "Error checking name existence" });
            }
            if (nameResult.length > 0) {
                return res.status(400).json({ error: "Club name already in use, You may want to consider appending your city name to make it unique." });
            }

            bcrypt.hash(password.toString(), salt, (hashErr, hash) => {
                if (hashErr) {
                    return res.status(500).json({ error: "Error hashing password" });
                }

                const sql = "INSERT INTO clubs (`name`, `email`, `password`, `address`, `description`, `profile_photo`) VALUES (?, ?, ?, ?, ?, ?)";
                const values = [name, email, hash, address, description, profile_photo];
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

// Club Login Route
router.post('/login', (req, res) => {
    const sql = 'SELECT * FROM clubs WHERE email=?';
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
                    const club_id = data[0].club_id
                    const club_token = jwt.sign({ name }, clubTokenSecretKey, { expiresIn: '1d' });
                    // res.cookie('club_token', club_token);
                    res.cookie('user_token', club_token, {
                        httpOnly: true,  // Ensure the cookie is not accessible by JavaScript (for security)
                        secure: true,    // Use 'true' in production if you're using HTTPS
                        sameSite: 'none' // Required for cross-origin requests (especially if frontend/backend are on different domains)
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

const verifyClub = (req, res, next) => {
    const club_token = req.cookies.club_token;
    if (!club_token) {
        return res.json({ error: "You are not authenticated" });
    } else {
        jwt.verify(club_token, clubTokenSecretKey, (err, decoded) => {
            if (err) {
                return res.json({ error: "Error in club token" });
            } else {
                req.name = decoded.name;

                // Retrieve club data including profile_photo
                const sql = 'SELECT name, profile_photo ,club_id FROM clubs WHERE name=?';
                db.query(sql, [req.name], (err, data) => {
                    if (err) {
                        return res.status(500).json({ error: "Error retrieving club data" });
                    }
                    req.clubData = data[0]; // Assuming there's only one club with this name
                    next();
                });
            }
        });
    }
};

// Protected Route for Club
router.get('/', verifyClub, (req, res) => {
    if (req.clubData.profile_photo) {
        return res.json({ status: "Success", club_id: req.clubData.club_id, name: req.clubData.name, profile_photo: (req.clubData.profile_photo).toString() });
    }
    return res.json({ status: "Success", club_id: req.clubData.club_id, name: req.clubData.name, profile_photo: (req.clubData.profile_photo) });
});

// Club Logout Route
router.get('/logout', (req, res) => {
    res.clearCookie('club_token');
    return res.json({ status: "Success" });
});

router.post('/addGround', upload.array('photos', 4), (req, res) => {
    const { club_id, type, description, start_time, end_time, price } = req.body;
    const photos = req.body.photos; // Get paths of uploaded photos

    const sql = "INSERT INTO grounds (`club_id`, `type`, `description`,`start_time`, `end_time`, `price`, `photo1`,`photo2`,`photo3`,`photo4`) VALUES (?, ?, ?, ?, ?, ?,?,?,?,?)";
    let values;

    if (photos && photos.length > 0) {
        values = [club_id, type, description, start_time, end_time, price, photos[0], photos[1], photos[2], photos[3]];
    } else {
        values = [club_id, type, description, start_time, end_time, price, null, null, null, null]; // Provide null values for photos
    }

    db.query(sql, values, (insertErr, result) => {
        if (insertErr) {
            return res.status(500).json({ error: "Error inserting data into database" });
        }
        return res.json({ status: "Success" });
    });
});

router.post('/addActivity', upload.array('photos', 4), (req, res) => {
    const { club_id, activity_name, category, description, age_group, start_date, end_date, start_time, end_time, instructor_info, capacity, price, contact_information } = req.body;
    const photos = req.body.photos; // Get paths of uploaded photos

    // Validate if start_date is later than end_date
    if (new Date(start_date) > new Date(end_date)) {
        return res.status(400).json({ error: "Start date cannot be later than end date" });
    }

    const sql = "INSERT INTO activities (`club_id`, `activity_name`, `category`,`description`, `age_group`, `start_date`, `end_date`,`start_time`,`end_time`,`instructor_info`,`capacity`,`price`,`photo1`,`photo2`,`photo3`,`photo4`,`contact_information`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    let values;

    if (photos && photos.length > 0) {
        values = [club_id, activity_name, category, description, age_group, start_date, end_date, start_time, end_time, instructor_info, capacity, price, photos[0], photos[1], photos[2], photos[3], contact_information];
    } else {
        values = [club_id, activity_name, category, description, age_group, start_date, end_date, start_time, end_time, instructor_info, capacity, price, null, null, null, null, contact_information];
    }

    db.query(sql, values, (insertErr, result) => {
        if (insertErr) {
            console.log(insertErr)
            return res.status(500).json({ error: "Error inserting data into database" });
        }
        return res.json({ status: "Success" });
    });
});


router.get('/grounds/:clubId', (req, res) => {
    const clubId = req.params.clubId;
    const sql = `SELECT 
        g.ground_id, 
        g.type, 
        g.description,
        g.visibility,
        TIME_FORMAT(g.start_time, '%H:%i') AS start_time, 
        TIME_FORMAT(g.end_time, '%H:%i') AS end_time, 
        g.price, 
        c.name AS club_name,
        g.photo1,
        g.photo2,
        g.photo3,
        g.photo4
    FROM grounds AS g
    INNER JOIN clubs AS c ON g.club_id = c.club_id
    WHERE g.club_id = ?`;

    db.query(sql, [clubId], (err, results) => {
        if (err) {
            console.error("Error fetching ground data:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        const groundsWithPhotos = results.map(ground => ({
            ...ground,
            photo1: ground.photo1 ? ground.photo1.toString() : null,
            photo2: ground.photo2 ? ground.photo2.toString() : null,
            photo3: ground.photo3 ? ground.photo3.toString() : null,
            photo4: ground.photo4 ? ground.photo4.toString() : null
        }));

        res.json({ status: "Success", grounds: groundsWithPhotos });
    });
});

router.get('/activities/:clubId', (req, res) => {
    const clubId = req.params.clubId;
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
        a.photo1,
        a.photo2,
        a.photo3,
        a.photo4,
        a.contact_information,
        a.visibility
    FROM activities AS a
    WHERE a.club_id = ?`;

    db.query(sql, [clubId], (err, results) => {
        if (err) {
            console.error("Error fetching activities data:", err);
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

// Route to get user's bookings
router.get('/bookings', verifyClub, (req, res) => {
    const club_id = req.clubData.club_id;
    const currentDate = new Date().toISOString().split('T')[0]; // Get current date in YYYY-MM-DD format

    const sql = `SELECT b.booking_id, DATE_FORMAT(b.date, '%Y-%m-%d') AS date,g.type AS ground_type,b.status, b.booking_start_time, b.booking_end_time, u.name AS user_name
                 FROM bookings AS b
                 INNER JOIN grounds AS g ON b.ground_id = g.ground_id
                 INNER JOIN clubs AS c ON g.club_id = c.club_id
                 INNER JOIN users AS u ON b.user_id = u.user_id
                 WHERE g.club_id = ? `;

    db.query(sql, [club_id, currentDate], (err, results) => {
        if (err) {
            console.error("Error fetching user's bookings:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }
        res.json({ status: "Success", bookings: results });
    });
});


router.post('/updateGround', verifyClub, upload.array('photos', 4), (req, res) => {
    const groundId = req.body.ground_id;
    const club_id = req.clubData.club_id;
    const { type, description, start_time, end_time, price, visibility } = req.body;
    const photos = req.body.photos; // Get paths of uploaded photos

    // Initialize arrays to hold values and update queries
    const updateValues = [];
    const updateQueries = [];

    // Build update queries and values for each field that is provided
    if (club_id) {
        updateQueries.push("club_id = ?");
        updateValues.push(club_id);
    }
    if (type) {
        updateQueries.push("type = ?");
        updateValues.push(type);
    }
    if (description) {
        updateQueries.push("description = ?");
        updateValues.push(description);
    }
    if (start_time) {
        updateQueries.push("start_time = ?");
        updateValues.push(start_time);
    }
    if (end_time) {
        updateQueries.push("end_time = ?");
        updateValues.push(end_time);
    }
    if (price) {
        updateQueries.push("price = ?");
        updateValues.push(price);
    }
    if (visibility) {
        updateQueries.push("visibility = ?");
        updateValues.push(visibility);
    }
    if (photos && photos.length > 0) {
        // If photos are provided, update photo paths
        for (let i = 0; i < photos.length; i++) {
            updateQueries.push(`photo${i + 1} = ?`);
            updateValues.push(photos[i]);
        }
    }

    // Construct the SQL update query
    let sql = "UPDATE grounds SET " + updateQueries.join(', ') + " WHERE ground_id = ?";
    updateValues.push(groundId);

    db.query(sql, updateValues, (updateErr, updateResult) => {
        if (updateErr) {
            return res.status(500).json({ error: "Error updating ground details" });
        }

        return res.json({ status: "Success", message: "Ground details updated successfully" });
    });
});

router.post('/updateActivity', verifyClub, upload.array('photos', 4), (req, res) => {
    const activityId = req.body.activity_id;
    const { contact_information, description, start_time, end_time, age_group, start_date, end_date, price, visibility } = req.body;
    const photos = req.body.photos; // Get paths of uploaded photos

    // Initialize arrays to hold values and update queries
    const updateValues = [];
    const updateQueries = [];

    // Build update queries and values for each field that is provided

    if (description) {
        updateQueries.push("description = ?");
        updateValues.push(description);
    }
    if (contact_information) {
        updateQueries.push("contact_information = ?");
        updateValues.push(contact_information);
    }
    if (age_group) {
        updateQueries.push("age_group = ?");
        updateValues.push(age_group);
    }
    if (start_date) {
        updateQueries.push("start_date = ?");
        updateValues.push(start_date);
    }
    if (end_date) {
        updateQueries.push("end_date = ?");
        updateValues.push(end_date);
    }
    if (start_time) {
        updateQueries.push("start_time = ?");
        updateValues.push(start_time);
    }
    if (end_time) {
        updateQueries.push("end_time = ?");
        updateValues.push(end_time);
    }
    if (price) {
        updateQueries.push("price = ?");
        updateValues.push(price);
    }
    if (visibility) {
        updateQueries.push("visibility = ?");
        updateValues.push(visibility);
    }
    if (photos && photos.length > 0) {
        // If photos are provided, update photo paths
        for (let i = 0; i < photos.length; i++) {
            updateQueries.push(`photo${i + 1} = ?`);
            updateValues.push(photos[i]);
        }
    }

    // Construct the SQL update query
    let sql = "UPDATE activities SET " + updateQueries.join(', ') + " WHERE activity_id = ?";
    updateValues.push(activityId);
    db.query(sql, updateValues, (updateErr, updateResult) => {
        if (updateErr) {
            console.log(updateErr)
            return res.status(500).json({ error: "Error updating ground details" });
        }

        return res.json({ status: "Success", message: "Ground details updated successfully" });
    });
});

router.post('/checkCredentials', (req, res) => {
    const { userId, password } = req.body;

    // Query to retrieve user data based on userId
    const getUserQuery = 'SELECT * FROM clubs WHERE club_id = ?';

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

router.post('/grounds/:groundId', verifyClub, (req, res) => {
    const groundId = req.params.groundId;
    const clubId = req.clubData.club_id;

    // Query to check if there are any bookings associated with the ground
    const checkBookingsSql = "SELECT COUNT(*) AS count FROM bookings WHERE ground_id = ?";
    db.query(checkBookingsSql, [groundId], (err, result) => {
        if (err) {
            console.error("Error checking bookings:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        const numberOfBookings = result[0].count;

        if (numberOfBookings > 0) {
            // If there are bookings associated with the ground, return an error message
            return res.status(401).json({ status: "Error", error: "Cannot delete ground with existing bookings" });
        }

        // If there are no bookings associated with the ground, proceed with deleting it
        const deleteGroundSql = "DELETE FROM grounds WHERE ground_id = ? AND club_id = ?";
        db.query(deleteGroundSql, [groundId, clubId], (err, result) => {
            if (err) {
                console.error("Error deleting ground:", err);
                return res.status(500).json({ status: "Error", error: "Internal Server Error" });
            }

            if (result.affectedRows === 0) {
                // If no rows were affected, it means the ground was not found or does not belong to the club
                return res.status(404).json({ status: "Error", error: "Ground not found or does not belong to the club" });
            }

            // If the ground was successfully deleted
            return res.json({ status: "Success", message: "Ground deleted successfully" });
        });
    });
});

router.get('/inquiries/:activityId', (req, res) => {
    const activityId = req.params.activityId;

    const sql = `
        SELECT activity_inquiries.*, users.name AS user_name
        FROM activity_inquiries
        INNER JOIN users ON activity_inquiries.user_id = users.user_id
        WHERE activity_inquiries.activity_id = ?`;

    db.query(sql, [activityId], (err, results) => {
        if (err) {
            console.error("Error fetching inquiries:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        res.json({ status: "Success", inquiries: results });
    });
});


router.post('/updateInquiryStatus/:inquiryId', (req, res) => {
    const inquiryId = req.params.inquiryId;
    const { status } = req.body;


    // Update the status of the inquiry in the database
    const updateQuery = 'UPDATE activity_inquiries SET status = ? WHERE inquiry_id = ?';
    db.query(updateQuery, [status, inquiryId], (err, result) => {
        if (err) {
            console.error("Error updating inquiry status:", err);
            return res.status(500).json({ error: "Internal Server Error" });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Inquiry not found" });
        }

        return res.json({ status: "Success", message: "Inquiry status updated successfully" });
    });
});

// Club Wallet Route
router.get('/wallet/balance', verifyClub, (req, res) => {
    const club_id = req.clubData.club_id;

    // Check if club's wallet exists
    const checkWalletQuery = 'SELECT * FROM club_wallet WHERE club_id = ?';

    // Execute the query
    db.query(checkWalletQuery, [club_id], (err, results) => {
        if (err) {
            console.error("Error checking club wallet:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        if (results.length === 0) {
            // If club's wallet doesn't exist, create one
            const createWalletQuery = 'INSERT INTO club_wallet (club_id, balance) VALUES (?, 0)';
            db.query(createWalletQuery, [club_id], (createErr, createResult) => {
                if (createErr) {
                    console.error("Error creating club wallet:", createErr);
                    return res.status(500).json({ status: "Error", error: "Internal Server Error" });
                }

                // Wallet created successfully, return balance as 0
                res.json({ status: "Success", wallet_balance: 0 });
            });
        } else {
            // Club's wallet exists, retrieve the balance
            const walletBalance = results[0].balance;
            res.json({ status: "Success", wallet_balance: walletBalance });
        }
    });
});

router.get('/transactions', verifyClub, (req, res) => {
    const clubId = req.clubData.club_id;

    // Query to retrieve transactions along with operation and user name
    const getTransactionsQuery = `
        SELECT wt.transaction_id, wt.transaction_type, wt.operation, wt.amount, wt.transaction_time, wt.related_type, 
               u.name AS user_name
        FROM wallet_transactions wt
        LEFT JOIN users u ON wt.user_id = u.user_id
        WHERE wt.club_id = ? AND wt.related_type='club'`;

    // Execute the query
    db.query(getTransactionsQuery, [clubId], (err, results) => {
        if (err) {
            console.error("Error fetching transactions:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }

        // Send the retrieved transactions data as JSON response
        res.json({ status: "Success", transactions: results });
    });
});


router.get('/stats', verifyClub, (req, res) => {
    const clubId = req.clubData.club_id;
    const { timePeriod } = req.query;

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

    const sqlTotalConfirmedBookings = `
        SELECT COUNT(*) AS totalConfirmedBookings
        FROM bookings b
        INNER JOIN grounds g ON b.ground_id = g.ground_id
        WHERE g.club_id = ? AND b.status = 'confirmed' AND b.date >= ?;
    `;

    const sqlTotalCancelledBookings = `
        SELECT COUNT(*) AS totalCancelledBookings
        FROM bookings b
        INNER JOIN grounds g ON b.ground_id = g.ground_id
        WHERE g.club_id = ? AND b.status = 'cancelled' AND b.date >= ?;
    `;

    const sqlTotalSlotsSpent = `
        SELECT SUM(TIMESTAMPDIFF(HOUR, b.booking_start_time, b.booking_end_time)) AS totalSlotsSpent
        FROM bookings b
        INNER JOIN grounds g ON b.ground_id = g.ground_id
        WHERE g.club_id = ? AND b.date >= ? AND b.status='confirmed';
    `;

    const sqlTotalIncomeGenerated = `
        SELECT SUM(TIMESTAMPDIFF(HOUR, b.booking_start_time, b.booking_end_time) * g.price) AS totalIncomeGenerated
        FROM bookings b
        INNER JOIN grounds g ON b.ground_id = g.ground_id
        WHERE g.club_id = ? AND b.date >= ? AND b.status='confirmed';
    `;

    const sqlMostBookedGroundType = `
        SELECT g.type AS mostBookedGroundType
        FROM grounds g
        JOIN (
            SELECT ground_id, COUNT(*) AS booking_count
            FROM bookings
            WHERE ground_id IN (
                SELECT ground_id FROM grounds WHERE club_id = ?
            ) AND status = 'confirmed'
            GROUP BY ground_id
            ORDER BY booking_count DESC
            LIMIT 1
        ) AS b ON g.ground_id = b.ground_id;
    `;

    const sqlMostBookedTimeSlot = `
        SELECT TIME(b.booking_start_time) AS mostBookedTimeSlot
        FROM bookings b
        INNER JOIN grounds g ON b.ground_id = g.ground_id
        WHERE g.club_id = ?
        GROUP BY TIME(b.booking_start_time)
        ORDER BY COUNT(*) DESC
        LIMIT 1;
    `;

    const sqlMostBookedUser = `
        SELECT u.user_id, u.name, COUNT(*) AS totalBookings
        FROM users u
        INNER JOIN bookings b ON u.user_id = b.user_id
        INNER JOIN grounds g ON b.ground_id = g.ground_id
        WHERE g.club_id = ? AND b.status = 'confirmed'
        GROUP BY u.user_id
        ORDER BY totalBookings DESC
        LIMIT 1;
    `;

    db.query(sqlTotalConfirmedBookings, [clubId, startDate], (err, results1) => {
        if (err) {
            console.error("Error fetching total confirmed bookings:", err);
            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
        }
        db.query(sqlTotalCancelledBookings, [clubId, startDate], (err, results2) => {
            if (err) {
                console.error("Error fetching total cancelled bookings:", err);
                return res.status(500).json({ status: "Error", error: "Internal Server Error" });
            }
            db.query(sqlTotalSlotsSpent, [clubId, startDate], (err, results3) => {
                if (err) {
                    console.error("Error fetching total slots spent:", err);
                    return res.status(500).json({ status: "Error", error: "Internal Server Error" });
                }
                db.query(sqlTotalIncomeGenerated, [clubId, startDate], (err, results4) => {
                    if (err) {
                        console.error("Error fetching total income generated:", err);
                        return res.status(500).json({ status: "Error", error: "Internal Server Error" });
                    }
                    db.query(sqlMostBookedGroundType, [clubId], (err, results5) => {
                        if (err) {
                            console.error("Error fetching most booked ground type:", err);
                            return res.status(500).json({ status: "Error", error: "Internal Server Error" });
                        }
                        db.query(sqlMostBookedTimeSlot, [clubId], (err, results6) => {
                            if (err) {
                                console.error("Error fetching most booked time slot:", err);
                                return res.status(500).json({ status: "Error", error: "Internal Server Error" });
                            }
                            db.query(sqlMostBookedUser, [clubId], (err, results7) => {
                                if (err) {
                                    console.error("Error fetching most booked user:", err);
                                    return res.status(500).json({ status: "Error", error: "Internal Server Error" });
                                }

                                // Combine all results and send response
                                const statistics = {
                                    totalConfirmedBookings: results1[0].totalConfirmedBookings,
                                    totalCancelledBookings: results2[0].totalCancelledBookings,
                                    totalSlotsSpent: results3[0].totalSlotsSpent,
                                    totalIncomeGenerated: results4[0].totalIncomeGenerated,
                                    mostBookedGroundType: results5.length ? results5[0].mostBookedGroundType : null,
                                    mostBookedTimeSlot: results6.length ? results6[0].mostBookedTimeSlot : null,
                                    mostBookedUser: results6.length ? results7[0] : null
                                };
                                console.log(statistics)
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
