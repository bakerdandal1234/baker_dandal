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

    // const verifyEmailMiddleware = async (req, res, next) => {
    //   try {
    //     // الحصول على معرف المستخدم (user ID) من `req.user`، والذي يمكن تعيينه عبر JWT
    //     const userId = req.user && req.user.id;
    //     if (!userId) {
    //       return res.status(401).json({ message: 'Unauthorized: No user ID provided' });
    //     }
    
    //     // البحث عن المستخدم والتحقق من حالته
    //     const user = await Auth.findById(userId);
    //     if (!user) {
    //       return res.status(404).json({ message: 'User not found' });
    //     }
    
    //     // التحقق مما إذا كان المستخدم قد قام بتفعيل البريد الإلكتروني
    //     if (!user.isVerified) {
    //       return res.status(403).json({ message: 'Access denied: Please verify your email address' });
    //     }
    
    //     // إذا كان المستخدم موثقًا، تابع إلى الخطوة التالية
    //     next();
    //   } catch (error) {
    //     console.error('Error verifying email:', error);
    //     res.status(500).json({ message: 'Server error' });
    //   }
    // };
    
  
  //   const isAuthenticated = async (req, res, next) => {
      
  //     const token = req.cookies.jwt;
  
  //     if (!token) return res.status(401).json({ error: "Access denied." });
  
  //     try {
  //         const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
  //         const user = await Auth.findById(decoded.id);
          
  //         if (!user || !user.isVerified) {
  //             return res.status(403).json({ error: "Account not verified or user not found." });
  //         }
  
  //         req.user = user;
  //         next();
  //     } catch (error) {
  //         res.status(403).json({ error: "Invalid token." });
  //     }
  // };
  
  
    module.exports ={ requireAuth,checkIfUser}