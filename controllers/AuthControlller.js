const Auth = require("../models/signupSchema")
const bcrypt = require("bcrypt");
var jwt = require("jsonwebtoken");
const { check, validationResult } = require("express-validator");


const { sendVerificationEmail } = require('../mails');




const get_welcome=(req, res) => {
    res.render("welcome");
  }

  const get_login=(req, res) => {
    res.render("auth/login");
  }
  const get_signup=(req, res) => {
    res.render("auth/signup");
  }
  const get_signout=(req, res) => {
    res.cookie("jwt", "", { maxAge: 1 });
    res.redirect("/");
  }
  const ok = async (req, res) => {
    try {
      const objError = validationResult(req);
      console.log(objError.errors);
      if (objError.errors.length > 0) {
        return res.json({ validationError: objError.errors });
      }
  
      const isCurrentEmail = await Auth.findOne({ email: req.body.email });
      if (isCurrentEmail) {
        return res.json({ existEmail: "Email already exist" });
      }
  
      const newUser = await Auth.create(req.body);
      const token = jwt.sign({ _id: newUser._id }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });
  
      // أرسل الرد الأول فقط
      res.cookie("jwt", token, { httpOnly: true, maxAge: 86400000 });
      res.json({
        message: 'Registration successful! Please check your email for verification.',
        id: newUser._id
      });
  
      // بعد إرسال الرد، يمكنك الآن إرسال البريد الإلكتروني
      await sendVerificationEmail(newUser);
  
    } catch (error) {
      console.log(error);
      res.status(500).send("An error occurred");
    }
  };
  

  const kk=async (req, res) => {
    try {
      const loginUser = await Auth.findOne({ email: req.body.email });
      if (loginUser == null) {
        res.json({ notFoundEmail: "Email not found, try to sign up" });
      } else {
        const match = await bcrypt.compare(req.body.password, loginUser.password);
        if (match) {
          var token = jwt.sign({ id: loginUser._id }, process.env.JWT_SECRET_KEY);
          res.cookie("jwt", token, { httpOnly: true, maxAge: 86400000 });
          res.json({ id: loginUser._id })
        } else {
          res.json({
            passwordError: `Incorrect password for ${req.body.email}`,
          });
        }
      }
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "An unexpected error occurred" });
    }
  }



// verification email after login 
const verifyEmail = async (req, res) => {
  const { token } = req.query;

  try {
    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    const userId = decoded.id;

    // Find and update the user in one step
    const user = await Auth.findByIdAndUpdate(userId, { isVerified: true }, { new: true });

    if (!user) {
      return res.status(404).send( { message: 'User not found' });
    }

    // Check if the update was successful
    if (user.isVerified) {
      return  res.redirect('/home');;
      
    } else {
      return res.status(500).send({ message: 'Failed to update verification status.' });
    }
    
  } catch (error) {
    console.error("Verification error:", error);
    res.status(400).send( { message: 'Invalid or expired token' });
  }
};



 




  module.exports={ok,kk,get_welcome,get_login,get_signup,get_signout,verifyEmail}
