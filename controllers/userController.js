const Auth = require("../models/signupSchema");
var moment = require("moment");

require('dotenv').config()
var jwt = require("jsonwebtoken");
const cloudinary = require('cloudinary').v2
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.api_key,
  api_secret: process.env.api_secret
});
const user_index_get = (req, res) => {
  // result ==> array of objects
  var decoded = jwt.verify(req.cookies.jwt, process.env.JWT_SECRET_KEY);
  console.log(decoded.id)
  Auth.findById(decoded.id)
    .then((result) => {
      res.render("index", { arr: result.customerInfo, moment: moment });
    })
    .catch((err) => {
      console.log(err);
    });
};

const user_post = (req, res) => {
  var decoded = jwt.verify(req.cookies.jwt, process.env.JWT_SECRET_KEY);
  Auth.findByIdAndUpdate(decoded.id, { $push: { customerInfo: {
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email: req.body.email,
    phoneNumber: req.body.phoneNumber,
    age: req.body.age,
    country: req.body.country,
    gender: req.body.gender,
    createdAt: new Date(),
  } } })
    .then((result) => {
      console.log(result)
      res.redirect("/home");
    })
    .catch((err) => {
      console.log(err);
    });
};

const user_put = (req, res) => {
  console.log(req.body)
  Auth.updateOne({ "customerInfo._id": req.params.id }, {
    "customerInfo.$.firstName": req.body.firstName,
    "customerInfo.$.lastName": req.body.lastName,
    "customerInfo.$.email": req.body.email,
    "customerInfo.$.phoneNumber": req.body.phoneNumber,
    "customerInfo.$.age": req.body.age,
    "customerInfo.$.country": req.body.country,
    "customerInfo.$.gender": req.body.gender,
    "customerInfo.$.updatedAt": new Date(),

  })
    .then((result) => {
      res.redirect("/home");
    })
    .catch((err) => {
      console.log(err);
    });
};



//SECOND METHODDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD

// const user_delete = (req, res) => {
//   var decoded = jwt.verify(req.cookies.jwt, process.env.JWT_SECRET_KEY);
//   Auth.findByIdAndUpdate(decoded.id,{$pull:{customerInfo:{_id:req.params.id}}})
//     .then((result) => {
//       res.redirect("/home");
//     })
//     .catch((err) => {
//       console.log(err);
//     });
// };
const user_delete = (req, res) => {
  Auth.updateOne({ "customerInfo._id": req.params.id }, { $pull: { customerInfo: { _id: req.params.id } } })
    .then((result) => {
      res.redirect("/home");
    })
    .catch((err) => {
      console.log(err);
    });
};

// const user_view_get = (req, res) => {
//   // result ==> object
//   var decoded = jwt.verify(req.cookies.jwt, process.env.JWT_SECRET_KEY);
//   Auth.findById(decoded.id)
//     .then((result) => {
//       console.log(result)
//       res.render("user/view", { obj: result, moment: moment });
//     })
//     .catch((err) => {
//       console.log(err);
//     });
// };

const user_view_get = (req, res) => {
  // result ==> object
  Auth.findOne({ "customerInfo._id": req.params.id })
    .then((result) => {
      console.log(result)
      const clickedObject = result.customerInfo.find((item) => {
        return item._id == req.params.id;
      });
      res.render("user/view", { obj: clickedObject, moment: moment });
    })
    .catch((err) => {
      console.log(err);
    });
};

const user_edit_get = (req, res) => {
  Auth.findOne({ "customerInfo._id": req.params.id })
    .then((result) => {
      const clickedObject = result.customerInfo.find((item) => {
        return item._id == req.params.id;
      });
      console.log(clickedObject)
      res.render("user/edit", { obj: clickedObject, moment: moment });
    })
    .catch((err) => {
      console.log(err);
    });
};




const user_search_post = (req, res) => {
  var decoded = jwt.verify(req.cookies.jwt, process.env.JWT_SECRET_KEY);
  const searchText = req.body.searchText.trim();
  Auth.findOne({ _id: decoded.id })
    .then((result) => {
      console.log(result);
      const searchCustomer = result.customerInfo.filter((item) => {
        return (
          item.firstName.includes(searchText) || item.lastName.includes(searchText)
        )
      })
      console.log(searchCustomer)
      res.render("user/search", { arr: searchCustomer, moment: moment });
    })
    .catch((err) => {
      console.log(err);
    });
};





const user_add_get = (req, res) => {
  res.render("user/add");
};
const upload_image = (req, res, next) => {
  cloudinary.uploader.upload(req.file.path, { folder: "x-system/profile-imgs" }, async (error, result) => {
    // console.log(result, error);
    if (result) {
      console.log(result.secure_url)
      var decoded = jwt.verify(req.cookies.jwt, process.env.JWT_SECRET_KEY);
      const avatar = await Auth.findByIdAndUpdate(decoded.id, { profileImage: result.secure_url })
      console.log(avatar)
      res.redirect("/home")
    }
  });
}



module.exports = {
  user_index_get,
  user_edit_get,
  user_view_get,
  user_search_post,
  user_delete,
  user_put,
  user_add_get,
  user_post,
  upload_image
};
