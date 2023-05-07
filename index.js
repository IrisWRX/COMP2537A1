require("./utils.js");

require("dotenv").config();

const url = require("url");
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;
const port = process.env.PORT || 8080;
const app = express();
const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.set("view engine", "ejs");

const navLinks = [
  { name: "Home", link: "/" },
  { name: "Login", link: "/login" },
  { name: "Members", link: "/members" },
  { name: "Admin", link: "/admin" },
  { name: "404", link: "/dne" },
];

app.use("/", (req, res, next) => {
  app.locals.navLinks = navLinks;
  app.locals.currentURL = url.parse(req.url).pathname;
  next();
});

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  })
);

function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect("/login");
  }
}

function isAdmin(req) {
  if (req.session.user_type == "admin") {
    return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("errorMessage", {
      error: "Not Authorized",
    });
    return;
  } else {
    next();
  }
}
app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.render("index");
    return;
  } else {
    res.render("loggedin", {
      username: req.session.username,
    });
  }
});

app.get("/signup", (req, res) => {
  res.render("createUser");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  if (!username) {
    res.render("createUserFailed", {
      error: "Name",
    });
    return;
  }
  if (!email) {
    res.render("createUserFailed", {
      error: "Email",
    });
    return;
  }
  if (!password) {
    res.render("createUserFailed", {
      error: "Password",
    });
    return;
  }

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().max(20).required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ username, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/signup");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    username: username,
    email: email,
    password: hashedPassword,
    user_type: "user",
  });
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.username = username;
  req.session.cookie.maxAge = expireTime;

  res.redirect("/members");
  return;
});

app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().max(20).required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.render("logginginFailed1");
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ email: 1, username: 1, password: 1, user_type: 1, _id: 1 })
    .toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("invalid email");
    res.render("logginginFailed2", {
      error: "email",
    });
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
    return;
  } else {
    console.log("inncorrect password");
    res.render("logginginFailed2", {
      error: "password",
    });
    return;
  }
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
  }
  res.render("members", {
    user: req.session.username,
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
  const result = await userCollection
    .find()
    .project({ username: 1, user_type: 1 })
    .toArray();

  res.render("admin", {
    users: result,
  });
});

app.post("/promote", async (req, res) => {
  const username = req.body.username;
  await userCollection.findOneAndUpdate(
    { username: username },
    { $set: { user_type: "admin" } }
  );
  res.redirect("/admin");
});

app.post("/demote", async (req, res) => {
  const username = req.body.username;
  await userCollection.findOneAndUpdate(
    { username: username },
    { $set: { user_type: "user" } }
  );
  res.redirect("/admin");
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
