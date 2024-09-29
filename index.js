import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import bcrypt from 'bcrypt';
import session from 'express-session';
import passport from 'passport';
import { Strategy } from 'passport-local';
import GoogleStrategy from 'passport-google-oauth2';
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

//middleware
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24
  }
}));
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) =>{
  req.logout(function (err) {
    if(err){
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs", { name: req.user.name }); // Pass 'name' to secrets.ejs
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

//failed
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/",
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
  const name = req.body.name;

  const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);
  //register
  try{
    if(checkResult.rows.length > 0){
      req.redirect("/login");
    }else{
      //password hashing
      bcrypt.hash(password, saltRounds, async (err, hash) =>{
        if(err){
          console.log("Error to hashing:", err);
        }
        const result = await db.query("INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING *", [email, hash, name]);
        const user = result.rows[0];
        req.login(user, (err) =>{
          console.log("success");
          res.redirect("/secrets");
        });
      });
    }
  }
  catch(err){
    console.log(err)
  }
});

passport.use("local",
  new Strategy(async function verify(username, password, cb) {
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [username]);

    if (checkResult.rows.length > 0) {
      const user = checkResult.rows[0];
      const storedPassword = user.password;

      bcrypt.compare(password, storedPassword, (err, valid) => {
        if (err) {
          console.log("Error comparing password: ", err);
          return cb(err);
        }
        if (valid) {
          return cb(null, user); // Pass 'user' object to serializeUser
        } else if(password === storedPassword){
          return cb(null, user)
        }
        else {
          return cb(null, false); // Password incorrect
        }
      });
    } else {
      return cb("User not found"); // User not found
    }
  } catch (err) {
    return cb(err);
  }
}));

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        let user;
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING *",
            [profile.email, "google", profile.displayName]
          );
          user = newUser.rows[0];
        } else {
          user = result.rows[0];
        }

        // Pastikan login setelah autentikasi Google berhasil
        cb(null, user);
      } catch (err) {
        return cb(err);
      }
    }
  )
);


passport.serializeUser((user, cb) => {
  cb(null, user.id); // Save user id in session
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = result.rows[0];
    cb(null, user); // Retrieve the full user object, including id and email
  } catch (err) {
    cb(err);
  }
});


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});


