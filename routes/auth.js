const express = require("express");
const passport = require('passport');
const router = express.Router();
const User = require("../models/User");

// Bcrypt to encrypt passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;

const mailer = require("../configs/nodemailer.config");
const randomToken = require("random-token");

// User sign up
router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
  let token = randomToken(16);
  const { username, password, email } = req.body;

  if (username === "" || password === "") {
    res.render("auth/signup", { message: "Indicate username and password" });
    return;
  }

  User.findOne({ username }, "username", (err, user) => {
    if (user !== null) {
      res.render("auth/signup", { message: "The username already exists" });
      return;
    }

    const salt = bcrypt.genSaltSync(bcryptSalt);
    const hashPass = bcrypt.hashSync(password, salt);

    let message = `Your confirmation code is: http://localhost:3000/auth/confirm/${token}`;
    let subject = "Confirmation code for ExpressNodemailer";

    mailer.sendMail({
      from: '"My Awesome Project" <myawesome@project.com>',
      to: email,
      subject: subject,
      text: message,
      html: `<b>${message}</b>`
    })
      .then(info => console.log(info))
      .catch(error => console.log("The email has not been sent", error));

  const newUser = new User({
      username,
      password: hashPass, 
      email,
      confirmationCode: token
    });

    newUser.save()
    .then(() => {
      res.redirect("/");
    })
    .catch(err => {
      res.render("auth/signup", { message: "Something went wrong" });
    })
  });
});

router.get("/auth/confirm/:confirmCode", (req, res, next) => {
  User.findOneAndUpdate({ confirmationCode: req.params.confirmCode }, { status: "Active" }, { new: true })
    .then(updateUser => res.render("auth/confirmation", { updatedUser }))
    .catch(error => console.log("Your account has not been confirmed", error))
});

// User log in
router.get("/login", (req, res, next) => {
  res.render("auth/login", { "message": req.flash("error") });
});

router.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/auth/login",
  failureFlash: true,
  passReqToCallback: true
}));

// User log out
router.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

module.exports = router;





