require("dotenv").config();
const sanitizeHTML = require("sanitize-html");
const cookieParser = require("cookie-parser");
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("better-sqlite3")("ourApp.db");
db.pragma("journal_mode = WAL");

// Database setup
const createTables = db.transaction(() => {
  db.prepare(
    `
        CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
    `
  ).run();

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS post (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    title STRING NOT NULL,
    body STRING NOT NULL,
    authorid INTEGER,
    FOREIGN KEY (authorid) REFERENCES user (id)
    )
    `
  ).run();
});
createTables();

const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static("public"));
app.use(cookieParser());

// Middleware for handling authentication
app.use((req, res, next) => {
  res.locals.errors = [];
  try {
    if (req.cookies.ourSimpleApp) {
      const decoded = jwt.verify(
        req.cookies.ourSimpleApp,
        process.env.JWTSECRET
      );
      req.user = decoded;
    } else {
      req.user = null;
    }
  } catch (err) {
    req.user = null;
  }

  res.locals.user = req.user;
  next();
});

// Middleware to ensure user is logged in
function mustBeLoggedIn(req, res, next) {
  if (req.user) {
    return next();
  }
  return res.redirect("/");
}

// Routes
app.get("/", (req, res) => {
  if (req.user) {
    const poststatement = db.prepare("SELECT * FROM post WHERE authorid = ? ORDER BY createdDate DESC");
    const posts = poststatement.all(req.user.userId);
    return res.render("dashboard", { posts });
  }
  res.render("homepage");
});

app.get("/logout", (req, res) => {
  res.clearCookie("ourSimpleApp", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });
  res.redirect("/");
});

app.get("/create-post", mustBeLoggedIn, (req, res) => {
  res.render("create-post");
});

app.post("/create-post", mustBeLoggedIn, (req, res) => {
  const errors = [];

  if (!req.body.title.trim()) errors.push("Add a title");
  if (!req.body.body.trim()) errors.push("Add a body");
  if (errors.length) return res.render("create-post", { errors });

  console.log("User object:", req.user);

  const statement = db.prepare(
    "INSERT INTO post (createdDate, title, body, authorid) VALUES (?, ?, ?, ?)"
  );
  const result = statement.run(
    new Date().toISOString(),
    req.body.title,
    req.body.body,
    req.user.userId
  );

  console.log("Creating post with author ID:", req.user.userId);

  const getPostStatement = db.prepare("SELECT * FROM post WHERE id = ?");
  const realPost = getPostStatement.get(result.lastInsertRowid);

  res.redirect(`/post/${realPost.id}`);
});

app.get("/post/:id", (req, res) => {
  const statement = db.prepare(
    `SELECT post.*, user.username 
     FROM post 
     LEFT JOIN user ON post.authorid = user.id 
     WHERE post.id = ?`
  );
  const post = statement.get(req.params.id);

  if (!post) {
    return res.redirect("/");
  }
  console.log(post);
  const isAuthor = post.authorid === req.userid;

  res.render("single-post", { post, isAuthor });
});

app.get("/edit-post/:id", mustBeLoggedIn, (req, res) => {
  // look up post
  const statement = db.prepare("SELECT * FROM post WHERE id = ?");
  const post = statement.get(req.params.id);

  if (post) {
    res.redirect("/");
  }
  // if not author, redirect to home page

  console.log("aurthorid:" + post.authorid);
  console.log("userid:" + post.userId);

  if (post.authorid !== req.userid) {
    return res.redirect("/");
  }

  //otherwise render edit post

  res.render("edit-post", { post });
});

app.post("/edit-post/:id", mustBeLoggedIn, (req, res) => {
  const statement = db.prepare("SELECT * FROM post WHERE id = ?");
  const post = statement.get(req.params.id);

  if (post) {
    res.redirect("/");
  }

  if (post.authorid !== req.userid) {
    return res.redirect("/");
  }

  const errors = sharedPostValidation(req);

  if (errors.length) {
    return res.render("edit-post", { errors });
  }

  const updateStatement = db.prepare(
    `UPDATE post SET title = ?, body = ? WHERE id = ?`
  );
  updateStatement.run(req.body.title, req.body.body, req.params.id);

  res.redirect(`/post/${(req, params.id)}`);
});

app.post("/delete-post/:id", mustBeLoggedIn, (req, res) => {
  const statement = db.prepare("SELECT * FROM post WHERE id = ?");
  const post = statement.get(req.params.id);

  if (post) {
    res.redirect("/");
  }

  if (post.authorid !== req.userid) {
    return res.redirect("/");
  }

  const deleteStatement = db.prepare("DELETE FROM post WHERE id = ?");
  deleteStatement.run(req.params.id);

  res.redirect("/");
});
app.post("/register", (req, res) => {
  const errors = [];
  req.body.username = req.body.username.trim();
  req.body.password = req.body.password.trim();

  if (
    db.prepare("SELECT * FROM user WHERE username = ?").get(req.body.username)
  ) {
    errors.push("User already exists");
  }

  if (req.body.username.length < 3 || req.body.username.length > 10) {
    errors.push("Username should be 3-10 characters long");
  }
  if (!/^[a-zA-Z0-9]+$/.test(req.body.username)) {
    errors.push("Username should only contain letters and numbers");
  }
  if (req.body.password.length < 6 || req.body.password.length > 70) {
    errors.push("Password should be 6-70 characters long");
  }

  if (errors.length) return res.render("homepage", { errors });

  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(req.body.password, salt);
  const result = db
    .prepare("INSERT INTO user (username, password) VALUES (?, ?)")
    .run(req.body.username, hashedPassword);

  const ourUser = db
    .prepare("SELECT * FROM user WHERE id = ?")
    .get(result.lastInsertRowid);
  const ourTokenValue = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, // 24 hours
      userId: ourUser.id,
      username: ourUser.username,
    },
    process.env.JWTSECRET
  );

  res.cookie("ourSimpleApp", ourTokenValue, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
  });

  res.redirect("/");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  const errors = [];
  req.body.username = req.body.username.trim();
  req.body.password = req.body.password.trim();

  const user = db
    .prepare("SELECT * FROM user WHERE username = ?")
    .get(req.body.username);

  if (!user) {
    errors.push("username or password not found");
  } else {
    const validPassword = bcrypt.compareSync(req.body.password, user.password);
    if (!validPassword) {
      errors.push("username or password not found");
    }
  }

  if (errors.length) {
    return res.render("login", { errors });
  }

  const ourTokenValue = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, // 24 hours
      userId: user.id,
      username: user.username,
    },
    process.env.JWTSECRET
  );

  res.cookie("ourSimpleApp", ourTokenValue, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
  });

  res.redirect("/");
});

app.listen(3000, () => console.log("Server running on port 3000"));
