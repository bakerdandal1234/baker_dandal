const express = require("express");
const router = express.Router();

var jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const bcryptjs = require("bcryptjs");
const { check, validationResult } = require("express-validator");

const Auth = require("../models/signupSchema");


const AuthControlller=require("../controllers/AuthControlller")
const userController = require("../controllers/userController");



const {  requireAuth } = require("../middleware/middleware")
const { checkIfUser } = require("../middleware/middleware")
const { verifyEmail } = require("../middleware/middleware")



const multer  = require('multer')
const upload = multer({storage: multer.diskStorage({})});








// GET Requst
router.get("*", checkIfUser)
router.post("*",checkIfUser)




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
    var token = jwt.sign({ id: checkUser._id }, process.env.JWT_SECRET_KEY);

    const transporter = nodemailer.createTransport({
      service:"gmail",
      host: 'smtp.gmail.com',
      port: 465, 
      secure: true, 
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
    const verificationLink = `${process.env.BASE_URL}/reset-password?token=${token}`;
    const mailOptions = {
    from:{ 
      name:"baker dandal",
      address:process.env.EMAIL_USER},
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

router.get('/reset-password', (req, res) => {
  const { token } = req.query;  // Access token from query string

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    res.render('auth/reset-password', { token: token });
  } catch (error) {
    console.error("JWT Verification Error: ", error);
    if (error instanceof jwt.TokenExpiredError) {
      return res.status(400).send('The token has expired. Please request a new one.');
    }
    return res.status(400).send('Invalid token');
  }
});



// Verification route
router.get("/verify-email", async (req, res) => {
  const token = req.query.token;

  if (!token) {
    return res.render("auth/verificationEmail", { message: "Invalid or expired token." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

    const user = await Auth.findById(decoded.id);

    if (!user) {
      return res.render("auth/verificationEmail", { message: "User not found." });
    }

    if (user.isVerified) {
      return res.render("auth/verificationEmail", { message: "Email is already verified." });
    }

    user.isVerified = true;
    await user.save();

    res.render("auth/verificationEmail", { message: "Email verified successfully! You can now log in." });

  } catch (error) {
    console.error('Verification error:', error);
    res.render("auth/verificationEmail", { message: "Invalid or expired token." });
  }
});










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










router.get("/home" ,requireAuth,verifyEmail, userController.user_index_get);

router.get("/edit/:id",requireAuth,verifyEmail,  userController.user_edit_get);

router.get("/view/:id", requireAuth,verifyEmail, userController.user_view_get);

router.post("/search", userController.user_search_post);

// DELETE Request
router.delete("/edit/:id", userController.user_delete);

// PUT Requst
router.put("/edit/:id", userController.user_put);

module.exports = router;
