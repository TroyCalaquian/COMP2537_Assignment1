require("./utils.js");

require("dotenv").config();

const express = require("express");
const app = express();

const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");

const port = 3000;

const Joi = require("joi");

const expireTime = 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true&w=majority`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(session({ 
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false, 
  resave: true
}
));


app.get("/", (req, res) => {
  var html = `
  <h1>Home Page</h1>
  <button onclick="location.href='/signup'">Sign up</button>
  <button onclick="location.href='/login'">Log in</button>
  `;
  if (req.session.authenticated) {
    res.redirect("/members");
  } else {
    res.send(html);
  }
});

app.get("/signup", (req, res) => {
  var html = `
  create user
  <form action="/createUser" method="post">
  <input type="text" name="username" placeholder="username" />
  <input type="email" name="email" placeholder="email" />
  <input type="password" name="password" placeholder="password" />
  <input type="submit" value="submit" />`;
  res.send(html);
});

app.get("/login", (req, res) => {
  var html = `
  login
  <form action="/loginUser" method="post">
  <input type="email" name="email" placeholder="email" />
  <input type="password" name="password" placeholder="password" />
  <input type="submit" value="submit" />`;
  res.send(html);
});

app.post("/createUser", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    username: Joi.string().alphanum().max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(30).required(),
  });

  const validationResult = schema.validate({ username, email, password });
  if (validationResult.error != null) {
    const errorDetails = validationResult.error.details[0];

    switch (errorDetails.context.key) {
      case "username":
        var html = "Please provide a valid username.";
        break;
      case "email":
        var html = "Please provide a valid email.";
        break;
      case "password":
        var html = "Please provide a valid password.";
        break;
      default:
        var html = "Invalid registration information.";
    }
    res.send(html + `<br/><br/><button onclick="location.href='/signup'">Try again</button>`);
  } else {
    var hashedPassword = await bcrypt.hash(password, 10);

    await userCollection.insertOne({username: username, email: email, password: hashedPassword});
    console.log("user created");
    req.session.authenticated = true;
    const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id:1}).toArray();
    req.session.username = result[0].username;
    req.session.cookie.maxAge = expireTime;
  
    res.redirect("/members");
  }
});

app.post('/loginUser', async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(30).required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    var html = `
    <h1>Invalid email/password combination</h1>
    <button onclick="location.href='/login'">Try again</button>
    `;
    res.send(html);
  }

  const result = await userCollection.find({email: email}).project({email: 1, username: 1, password: 1, _id:1}).toArray();

  console.log(result);
  if (result.length == 0) {
    res.send("user not found");
  }

  if (await bcrypt.compare(password, result[0].password)) {
    console.log("login success");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
    return;
  } else {
    console.log("login failed");
    res.send("login failed");
  }
});

app.get('/members', (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/');
    return;
  }
  var html = `
  <h1>Hello, ${req.session.username}.</h1>

  <button onclick="location.href='/logout'">Log out</button>
  `;
  res.send(html);
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 