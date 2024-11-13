const Auth = require("../models/signupSchema")
const bcrypt = require("bcrypt");
var jwt = require("jsonwebtoken");
const { check, validationResult } = require("express-validator");


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
const ok=  async (req, res) => {
    try {
  
  
      const objError = validationResult(req);
      console.log(objError.errors);
      if (objError.errors.length > 0) {
        return res.json({ validationError: objError.errors })
      }
  
      const isCurrentEmail = await Auth.findOne({ email: req.body.email })
      if (isCurrentEmail) {
        return res.json({ existEmail: "Email already exist" })
      }
  
  
      const newUser = await Auth.create(req.body)
      var token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET_KEY);
  
  
      res.cookie("jwt", token, { httpOnly: true, maxAge: 86400000 });
      res.json({ id: newUser._id })
    } catch (error) {
      console.log(error)
    }
  }

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

  module.exports={ok,kk,get_welcome,get_login,get_signup,get_signout}
