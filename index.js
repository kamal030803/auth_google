const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const passport = require("passport");
const Strategy = require("passport-local");
const GoogleStrategy = require("passport-google-oauth2");
const session = require("express-session");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;


const userSecretsSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  secret: {
    type: String
  },
});
const userSecrets = mongoose.model("userSecrets", userSecretsSchema);


mongoose.connect("mongodb://localhost:27017/users");

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", () => {
  console.log("Database connected");
});

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  console.log(req.user);

  if (req.isAuthenticated()) {
    try {
      const result = await userSecrets.findOne({ email: req.user.email });
      console.log(result);
      const secret = result.secret;
      if (secret) {
        res.render("secrets.ejs", { secret: secret });
      } else {
        res.render("secrets.ejs", { secret: "Jack Bauer is my hero." });
      }
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const user = await userSecrets.findOne({ email: email });

    if (user) {
      res.redirect("/login");
    } else {
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const newUser = new userSecrets({
        email: email,
        password: hashedPassword,
      });

      
      if (req.body.secret) {
        newUser.secret = req.body.secret;
      }

      await newUser.save();
      req.login(newUser, (err) => {
        if (err) {
          console.error("Error logging in user:", err);
        } else {
          console.log("User registered and logged in");
          res.redirect("/secrets");
        }
      });
    }
  } catch (err) {
    console.error("Error registering user:", err);
    res.redirect("/register");
  }
});

app.post("/submit", async function (req, res) {
  const submittedSecret = req.body.secret;
  console.log(req.user);
  try {
    await userSecrets.updateOne(
      { email: req.user.email },
      { $set: { secret: submittedSecret } }
    );
    res.redirect("/secrets");
  } catch (err) {
    console.log(err);
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const user = await userSecrets.findOne({ email: username });
      if (user) {
        const valid = await bcrypt.compare(password, user.password);
        if (valid) {
          return cb(null, user);
        }
      }
      return cb(null, false);
    } catch (err) {
      console.log(err);
      return cb(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        let user = await userSecrets.findOne({ email: profile.email });
        if (!user) {
          user = await userSecrets.create({
            email: profile.email,
            password: "google",
          });
        }
        return cb(null, user);
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const user = await userSecrets.findById(id);
    cb(null, user);
  } catch (err) {
    cb(err);
  }
});


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
