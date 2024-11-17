const mongoose = require("mongoose");
const Schema = mongoose.Schema;

// define the Schema (the structure of the article)
const userSchema = new Schema({
  username: String,
  email: String,
  password: String,
  profileImage:String,
  isVerified: { type: Boolean, default: false },
  customerInfo:[
    {
      firstName: String,
      lastName: String,
      email: String,
      phoneNumber: String,
      age: Number,
      country: String,
      gender: String,
      createdAt:Date,
      updatedAt:{type:Date,default:Date.now},
    }
  ]
}, );

const bcrypt = require('bcrypt');

userSchema.pre("save", async function (next) {
 const salt = await bcrypt.genSalt();
 this.password = await bcrypt.hash(this.password, salt);
 next();
});

// Create a model based on that schema
const Auth = mongoose.model("auth", userSchema);

// export the model
module.exports = Auth;
