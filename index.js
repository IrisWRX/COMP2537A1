require("./utils.js");

require("dotenv").config();
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

app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    var html = `
      <br>
      <form action="/signup" method="get">
        <button type="submit">Sign up</button>
      </form>
      <form action="/login" method="get">
        <button type="submit">Log in</button>
      </form>
    `;
    res.send(html);
    return;
  } else {
    var html = `<h1>Hello, ${req.session.username}!</h1>`;
    html += `
    <form action='/members' method='get''> 
      <button type ='submit'>Go to Members Ares</button>
    </form>
    <form action='/logout' method='get'> 
      <button type ='submit'>Logout</button>
    </form>`;
    res.send(html);
  }
});

app.get("/nosql-injection", async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

app.get("/signup", (req, res) => {
  var html = `
    <h1>Create User</h1>
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='name'><br>
    <br>
    <input name='email' type='email' placeholder='email'><br>
    <br>
    <input name='password' type='password' placeholder='password'><br>
    <br>
    <button>Submit</button>
    </form>
    `;
  res.send(html);
});

app.get("/login", (req, res) => {
  var html = `
  <h1>Log in</h1>
  <form action='/loggingin' method='post'>
  <input name='email' type='email' placeholder='email'><br>
  <br>
  <input name='password' type='password' placeholder='password'><br>
  <br>
  <button>Submit</button>
  </form>
  `;
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  if (!username) {
    res.send(`Name is required.<br><a href='/signup'>Try again</a>`);
  }
  if (!email) {
    res.send(`Email is required.<br><a href='/signup'>Try again</a>`);
  }
  if (!password) {
    res.send(`Password is required.<br><a href='/signup'>Try again</a>`);
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
    res.send(
      `Invalid email/password combination. <br><a href='/login'>Try again</a>`
    );
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ email: 1, username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("user not found");
    res.send("User not found.<br><br><a href='/login'>Try again</a>");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
    return;
  } else {
    console.log("incorrect password");
    res.send("Incorrect password.<br><br><a href='/login'>Try again</a>");
    return;
  }
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
  }

  const images = ["what.gif", "sup.gif", "again.gif"];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  var html = `<h1>Hello, ${req.session.username}!</h1>`;
  html += `<img src='${randomImage}' style='width:250px;'><br>`;
  html += `<br>`;
  html += `
  <form action='/logout' method='get'>
    <button>Log out</button>
  </form>
  `;
  res.send(html);
});

app.get("/loggedin", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
  }
  var html = `<h1>Hello, ${req.session.username}!</h1>`;

  html += `<form action='/members' method='get'>
             <button>Go to Members Area</button>
             </form>`;

  html += `<form action='/logout' method='get'>
             <button>Log out</button>
             </form>`;
  res.send(html);
});

app.get("/logout", (req, res) => {
  req.session.destroy();

  res.redirect("/");
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);

  var html = `Page not found - 404<br>`;
  // html += `<br>`;
  // html += `<img src='404.gif' style='width:250px;'>`;
  res.send(html);
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
