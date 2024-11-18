var jwt = require("jsonwebtoken");

const Auth = require("../models/signupSchema");



const requireAuth = (req, res, next) => {
  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, process.env.JWT_SECRET_KEY, (err) => {
      if (err) { res.redirect("/login"); } else { next(); }
    });
  } else {
    res.redirect("/login");
  }
};



const verifyEmail = async (req, res, next) => {
  const token = req.cookies.jwt;

  if (!token) {
    return res.redirect('/login'); 
  }

  try {
  
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);


    const user = await Auth.findById(decoded.id);
   
    
    if (!user || user.isVerified===false) {
      return res.redirect('/login');
    }

   
    next();

  } catch (error) {
    console.error('Authorization error:', error);
    res.redirect('/login'); 
  }
};







const checkIfUser = (req, res, next) => {
  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, process.env.JWT_SECRET_KEY, async (err, decoded) => {
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


module.exports = {  checkIfUser,requireAuth, verifyEmail}