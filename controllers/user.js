const User = require("../models/user");
const VerificationToken = require("../models/verificationToken");
const ResetToken = require("../models/resetToken");
const { sendError, createRandomBytes } = require("../utils/helper");
const jwt = require("jsonwebtoken");
const { generateOtp, mailTransport, generatePasswordResetLink } = require("../utils/mail");
const { isValidObjectId } = require("mongoose");
const { use } = require("../routes/user");


exports.createUser = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return sendError(res, "This email already exists!");
    }

    const newUser = new User({
      name,
      email,
      password,
    });

    const otp = generateOtp()
    const verificationToken = new VerificationToken({
      owner: newUser._id,
      token: otp
    })

    mailTransport().sendMail({
      from: 'naturemarksystems@email.com',
      to: newUser.email,
      subject: "Verify your email account",
      html: `<h1>${otp}</h1>`
    })

    await verificationToken.save();
    await newUser.save();
    res.status(201).json(newUser);
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
};

exports.signin = async (req, res) => {
  const { email, password } = req.body;
  if (!email.trim() || !password.trim())
    return sendError(res, "Email/Password is missing");

  const user = await User.findOne({ email });
  if (!user) return sendError(res, "User not found!");

  const isMatched = await user.comparePassword(password);
  if (!isMatched) return sendError(res, "Incorrect Password!");

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });

  res.json({
    success: true,
    user: {
      name: user.name,
      email: user.email,
      id: user._id,
      token: token
    },
  });
};

exports.verifyemail = async (req, res) => {
  const { userId, otp } = req.body;

  if (!userId || !otp.trim()) {
    return sendError(res, "Invalid request, missing parameters!!");
  }

  if (!isValidObjectId(userId)) {
    return sendError(res, "Invalid user id!");
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      return sendError(res, "User not found");
    }

    if (user.verified) {
      return sendError(res, "This email is already verified");
    }

    const token = await VerificationToken.findOne({ owner: user._id });
    if (!token) {
      return sendError(res, "Verification token not found");
    }

    const isMatched = await token.compareToken(otp);
    if (!isMatched) {
      return sendError(res, "Please provide a valid OTP");
    }

    user.verified = true;
    await user.save();

    await VerificationToken.findByIdAndDelete(token._id);

    mailTransport().sendMail({
      from: 'naturemarksystems@email.com',
      to: user.email,
      subject: "Welcome!",
      html: `<h1>Email verified successfully</h1>`
    });

    res.json({
      success: true,
      message: "Your email is verified.",
      user: {
        name: user.name,
        email: user.email,
        id: user._id
      }
    });
  } catch (error) {
    console.error("Error verifying email:", error);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
};

exports.forgotPassword = async (req,res)=>{
  const {email} = req.body;
  if(!email) return sendError(res, "Please provide a valid email!");

  const user = await User.findOne({email});
  if(!user) return sendError(res, "User not found");

  const token = await ResetToken.findOne({owner:user._id})
  if(token) return sendError(res, "Only after one hour you can request for another token");

  const RandomBytes = await createRandomBytes()
  const resetToken = new ResetToken({ owner: user._id, token: RandomBytes });
  await resetToken.save()

  const url = `http://localhost:3000/reset-password?token=${RandomBytes}&id=${user._id}`
  mailTransport().sendMail({
    from: 'naturemarksystems@email.com',
    to: user.email,
    subject: "Password Reset!",
    html: generatePasswordResetLink(url)
  });

  res.json({
    success:true,
    message: "Password reset link is sent to your email."
  })
}

exports.resetPassword = async (req,res) => {
  const {password} = req.body;
  const user = await User.findById(req.user._id);
  if(!user) return sendError(res,"User not found!")

  const isSamePassword = await user.comparePassword(password)
  if(isSamePassword) return sendError(res,"New password cannot be same as old password!!")

  if(password.trim().length < 8 || password.trim().length > 20)
  return sendError(res,"Password must be 8 to 20 characters long")

  user.password = password.trim();
  await user.save()

  await ResetToken.findOne({owner:user._id})

  mailTransport().sendMail({
    from: 'naturemarksystems@email.com',
    to: user.email,
    subject: "Password Reset!",
    html: `<h1>Password Reset successfully </br> Now you can login with new password</h1>`
  });

  res.json({
    success: true,
    message: "Password reset successfully"
  })

}