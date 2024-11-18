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
      const token = jwt.sign({ _id: newUser._id }, process.env.JWT_SECRET_KEY);
  
      // أرسل الرد الأول فقط
      res.cookie("jwt", token, { httpOnly: true, maxAge: 86400000 });
      res.json({
        message: 'Registration successful! Please check your email for verification.',
        id: newUser._id
      });
  
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
          res.json({ id: loginUser._id,message:"check your mailbox to continue" })
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








  module.exports={ok,kk,get_welcome,get_login,get_signup,get_signout}
