var jwt = require("jsonwebtoken");

const Auth = require("../models/signupSchema");



const requireAuth = (req, res, next) => {
    const token = req.cookies.jwt;
    
     if (token) {
        jwt.verify(token, "baker", (err) => {
      if (err) { res.redirect("/login"); } else {next();}
       });
       } else {
        res.redirect("/login");
    }};


    const checkIfUser = (req, res, next) => {
      const token = req.cookies.jwt;
      if (token) {
        jwt.verify(token, "baker", async (err, decoded) => {
          if (err) {
            res.locals.user = null;
            next();
          } else {
            const currentUser = await Auth.findById(decoded.id);
            res.locals.user = currentUser;
            next();
            
          }
        });
      } else {
        res.locals.user = null;
        next();
      }
    };
    module.exports ={ requireAuth,checkIfUser}