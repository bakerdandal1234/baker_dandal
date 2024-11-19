const express = require("express");
const router = express.Router();

const Auth=require("../models/signupSchema")

const userController = require("../controllers/userController");


var moment = require("moment");

const {requireAuth}=require("../middleware/middleware")
const {verifyEmail}=require("../middleware/middleware") 

router.get("",requireAuth,verifyEmail, userController.user_add_get);
// POST Requst
router.post("",requireAuth,verifyEmail, userController.user_post);

module.exports = router;
