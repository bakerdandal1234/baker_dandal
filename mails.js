const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

const transporter = nodemailer.createTransport({
  service:'gmail',
  host:"smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});


async function sendVerificationEmail(user) {
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET_KEY,);
  const verificationLink = `${process.env.BASE_URL}/verify-email?token=${token}`;
  const mailOptions = {
    from:{ 
      name:"baker dandal",
      address:process.env.EMAIL_USER},
    to: user.email,
    subject: 'Verify Your Email Address',
    html: `<p>Please verify your email by clicking on the link below:</p><a href="${verificationLink}">${verificationLink}</a>`,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent:', info.response);
  } catch (err) {
    console.error('Error sending email:', err);
  }
  
  
}

module.exports = { sendVerificationEmail };
