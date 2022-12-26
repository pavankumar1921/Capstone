const express = require("express");
const session = require("express-session");
const csrf = require("tiny-csrf");
const app = express();

const bodyParser = require("body-parser");
var cookieParser = require("cookie-parser");
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser("shh! some secret string"));
app.use(
  session({
    secret: "my-super-secret-key-21728173615375893",
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);
app.use(csrf("this_should_be_32_character_long", ["POST", "PUT", "DELETE"]));

const path = require("path");
const {admin} =require("./models")
app.set("views", path.join(__dirname, "views"));

const passport = require("passport");
const connectEnsureLogin = require("connect-ensure-login");

const flash = require("connect-flash");
const LocalStrategy = require("passport-local");
const bcrypt = require("bcrypt");

const saltRounds = 10;
app.use(bodyParser.json());




app.set("view engine", "ejs");
app.use(flash());
// eslint-disable-next-line no-undef
app.use(express.static(path.join(__dirname, "public")));
app.set("views", path.join(__dirname, "views"));



app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    (username, password, done) => {
      admin.findOne({ where: { email: username } })
        .then(async (user) => {
          const result = await bcrypt.compare(password, user.password);
          if (result) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Invalid password" });
          }
        })
        .catch(() => {
          return done(null,false,{
            message: "No account found for this mail",
          })
        });
    }
  )
);

  app.use(function(request, response, next) {
    response.locals.messages = request.flash();
    next();
});

passport.serializeUser((user, done) => {
  console.log("Serializing user in session", user.id);
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  admin.findByPk(id)
    .then((user) => {
      done(null, user);
    })
    .catch((error) => {
      done(error, null);
    });
});
app.get("/", async (request, response) => {
    response.render("index", {
      title: "Voting app",
      csrf: request.csrfToken(),
    });
  });

app.get("/signup", (request, response) => {
  try {
    response.render("signup", {
      title: "Signup",
      csrfToken: request.csrfToken(),
    });
  } catch (error) {
    console.log(error);
    return response.redirect("/signup");
  }
});

app.get("/login", (request, response) => {
    try {
      response.render("login", {
        title: "Login",
        csrfToken: request.csrfToken(),
      });
    } catch (error) {
      console.log(error);
      return response.redirect("/login");
    }
    
  });

  app.post("/admin", async (request, response) => {
    if (request.body.email.length == 0) {
      request.flash("error", "Email can not be empty!");
      return response.redirect("/signup");
    }
  
    if (request.body.firstName.length == 0) {
      request.flash("error", "First name can not be empty!");
      return response.redirect("/signup");
    }
    if (request.body.password.length < 8) {
      request.flash("error", "Password length should be minimun 8");
      return response.redirect("/signup");
    }
    const hashedPwd = await bcrypt.hash(request.body.password, saltRounds);
    console.log(hashedPwd);
  
    try {
      const user = await admin.create({
        firstName: request.body.firstName,
        lastName: request.body.lastName,
        email: request.body.email,
        password: hashedPwd,
      });
      request.login(user, (err) => {
        if (err) {
          console.log(err);
          response.redirect("/");
        }
        response.redirect("/election");
      });
    } catch (error) {
      console.log(error);
      return response.redirect("/signup");
    }
  });
module.exports = app;