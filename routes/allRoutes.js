const express = require("express");
const router = express.Router();
var jwt = require("jsonwebtoken");
const bcryptjs = require("bcryptjs");
const { check, validationResult } = require("express-validator");

const Auth = require("../models/signupSchema");
const AuthControlller=require("../controllers/AuthControlller")

const userController = require("../controllers/userController");



const { requireAuth } = require("../middleware/middleware")
const { checkIfUser } = require("../middleware/middleware")


var moment = require("moment");




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
router.post("/update-password",async(req,res)=>{
  try{
 const data=await Auth.findOne({email:req.body.email})
  if(data){
  const newpassword=await securePassword(req.body.password)
 const useerData= await Auth.updateOne({email:req.body.email},{$set:{password:newpassword}}) 
 res.json({success:true,  message:"your psw has been updated"})
  }else{
    res.json({success:false,msg:"email not found in database"})
  }
  }catch (error){
    res.status(500).send({ success: false, msg: error.message });
  }
})

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




router.get("/home", requireAuth, userController.user_index_get);

router.get("/edit/:id", requireAuth, userController.user_edit_get);

router.get("/view/:id", requireAuth, userController.user_view_get);

router.post("/search", userController.user_search_post);

// DELETE Request
router.delete("/edit/:id", userController.user_delete);

// PUT Requst
router.put("/edit/:id", userController.user_put);

module.exports = router;
