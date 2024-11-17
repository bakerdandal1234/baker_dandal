const express = require("express");
const router = express.Router();
var jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const { sendVerificationEmail } = require('../mails');
const bcryptjs = require("bcryptjs");
const { check, validationResult } = require("express-validator");

const Auth = require("../models/signupSchema");
const AuthControlller=require("../controllers/AuthControlller")

const userController = require("../controllers/userController");


const {  requireAuth } = require("../middleware/middleware")
const { checkIfUser } = require("../middleware/middleware")








// GET Requst
router.get("*", checkIfUser)
router.post("*",checkIfUser)

router.get("/verify",(req,res)=>{
  res.render("auth/verificationEmail")
})

const securePassword=async(password)=>{
  try{
    const passwordHash=await bcryptjs.hash(password,10);
    return passwordHash;
  }catch(error){
    res.send(error.message)
  }
}
router.post("/forget-password", async (req, res) => {
  try {
    const {email}=req.body;
    if (!email) {
      return res.json({ success: false, msg: "please provide a valid email" });
    }
    const checkUser=await Auth.findOne({email})
    if(!checkUser){
      return res.json({ success: false, msg: "user not found pleaser register" });
    }
    var token = jwt.sign({ id: checkUser._id }, process.env.JWT_SECRET_KEY,{expiresIn:"1h"});

    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT, 
      secure: false, 
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
    const verificationLink = `${process.env.BASE_URL}/reset-password?token=${token}`;
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify Your Email Address',
      html: `<p>Please verify your email by clicking on the link below:</p><a href="${verificationLink}">${verificationLink}</a>`,
    };

    try {
      const info = await transporter.sendMail(mailOptions);
     return  res.status(201).send({ success: true, msg: "Please check your mailbox to verify your email" });
    } catch (err) {
      console.error('Error sending email:', err);
    }

  } catch (error) {
    res.status(500).send({ success: false, msg: error.message });
  }
});


router.post('/reset-password/:token',async(req,res)=>{
  try{
const {token}=req.params
const {password}=req.body
  if(!password){
   return res.send({message:"please provide password"})
  }

  var decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
 const newPassword=await securePassword(password);
 const users=await Auth.findByIdAndUpdate(decoded.id,{password:newPassword},{new:true})
 if(users){
  res.status(200).send({ success: true, msg: "password has been verified" });
 }else {
  res.status(400).send({ success: false, msg: "User not found" });
}
 

  }catch (error) {
    res.status(500).send({ success: false, msg: error.message });
  }
})

router.get('/reset-password/:token', (req, res) => {
  const {token} = req.params;

  try {
    const decoded = jwt.verify(token,process.env.JWT_SECRET_KEY ); 
    res.render('auth/reset-password', { token: token }); 
  } catch (error) {
    console.error("JWT Verification Error: ", error);
    res.status(400).send('Invalid or expired token');
  }
});














const multer  = require('multer')
const upload = multer({storage: multer.diskStorage({})});


router.post('/update-profile', upload.single('avatar'),userController.upload_image )

router.get("/",AuthControlller.get_welcome);


router.get("/login",AuthControlller.get_login);
















router.get("/signup", AuthControlller.get_signup);

router.get("/signout", AuthControlller.get_signout);


router.post("/signup",[
  check("email", "Please provide a valid email").isEmail(),
  check("password", "Password must be at least 8 characters with 1 upper case letter and 1 number").matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/),
],AuthControlller.ok);


router.post("/login",AuthControlller.kk);



router.get('/verify-email', AuthControlller.verifyEmail);


router.get("/home" ,requireAuth, userController.user_index_get);

router.get("/edit/:id",requireAuth,  userController.user_edit_get);

router.get("/view/:id",requireAuth,  userController.user_view_get);

router.post("/search", userController.user_search_post);

// DELETE Request
router.delete("/edit/:id", userController.user_delete);

// PUT Requst
router.put("/edit/:id", userController.user_put);

module.exports = router;
