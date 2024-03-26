import express from "express";
import bodyParser from "body-parser";
import pg from 'pg';
import bcrypt from 'bcrypt';
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2"
import env from 'dotenv'
const app = express();
const port = 3000;
const client_ID = "your ID"
const client_secret="your secret"
// Middleware setup
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
env.config()
// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET ||"MYSESSION",
  resave: false,
  saveUninitialized: true,
  cookie:{
    maxAge:1000 *60*60*24,
  }
}));

// Initialize Passport and restore authentication state, if any, from the session
app.use(passport.initialize());
app.use(passport.session());

// Database connection
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "your db", // corrected database name
  password: "your password",
  port: 5433,
});
db.connect();

// Passport local strategy configuration
passport.use(new Strategy(async function verify(username, password, cb) {
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);

    if (checkResult.rows.length === 0) {
      return cb(null, false, { message: "User doesn't exist" });
    } else {
      const userFromDb = checkResult.rows[0];
      bcrypt.compare(password, userFromDb.password, function(err, result) {
        if (err) {
          return cb(err);
        }
        if (result) {
          return cb(null, userFromDb);
        } else {
          return cb(null, false, { message: "Incorrect password" });
        }
      });
    }
  } catch (error) {
    return cb(error);
  }
}));


passport.use(new GoogleStrategy({
  clientID: client_ID,
  clientSecret: client_secret,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
}, async (accessToken, refreshToken, profile, cb) => {
  console.log(profile);
  try {
    const result = await db.query("SELECT * FROM users where email = $1", [profile.email])
    if(result.rows.length ===0){
      const newuser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2)",
      [profile.email,"google"])
      cb(null, newuser.rows[0])
    }else{
      cb(null, result.rows[0])
    }
  } catch (error) {
    cb(error)
  }



}));

// Routes
app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"]
  })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  (req, res) => {
    // Successful authentication, redirect to secrets page or perform other actions
    res.redirect("/secrets");
  }
);

// Serialize and deserialize user
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

// Routes
app.get("/logout",(req, res)=>{

  req.logout((err)=>{
    if(err) console.log(err)
    res.redirect("/")
  })
})
app.get("/secrets", async(req, res) => {
console.log(req.user,"userrr")
 ////////////////UPDATED GET SECRETS ROUTE/////////////////
 if (req.isAuthenticated()) {
  try {
    const result = await db.query(
      `SELECT secret FROM users WHERE email = $1`,
      [req.user.email]
    );
    console.log(result);
    const secret = result.rows[0].secret;
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
app.post("/submit", async function (req, res) {
  const submittedSecret = req.body.secret;
  console.log(req.user);
  try {
    await db.query(`UPDATE users SET secret = $1 WHERE email = $2`, [
      submittedSecret,
      req.user.email,
    ]);
    res.redirect("/secrets");
  } catch (err) {
    console.log(err);
  }
});

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", async (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      bcrypt.hash(password, 10, async (err, hash) => {
        if (err) {
          res.send("We are facing some errors", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0]; // corrected array index
          req.login(user, (err) => {
            if (err) {
              console.log(err);
              res.redirect("/login");
            } else {
              res.redirect("/secrets");
            }
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}));

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
