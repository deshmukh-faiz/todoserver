import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import Joi from "joi";

const PORT = process.env.PORT || 8081

const saltRounds = 10; // Define the number of salt rounds

const app = express();
app.use(express.json());

app.use(cors({ credentials: true, origin: 'http://localhost:3000' }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use(cookieParser());

const dbInfo = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME
};

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ Error: "You are not authenticated" });
  } else {
    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
      // Change jwt.verifyUser to jwt.verify
      if (err) {
        return res.json({ Error: "Token is not okk " });
      } else {
        req.name = decoded.name;
        next();
      }
    });
  }
};


// How to use html in express js:
app.get('/SS', (req, res) => {
  const htmlContent = '<html><head><title>My Express App</title></head><body><h1>Hello, Faiz!</h1></body></html>';
  res.send(htmlContent);
});
// How to use html in express js:


app.get("/GetEmployees", (req, res) => {
  const sql = "SELECT * FROM employee_details";
  dbInfo.query(sql, (err, result) => {
    if (err) {
      return res.json({ Message: "Error inside server", err: err });
    } else {
      return res.json({ success: true, data: result });
    }
  });
});

app.get("/", verifyUser, (req, res) => {
  return res.json({ Status: "Success", name: req.name });
});

app.post("/employee_details", (req, res) => {
  const sql =
    "INSERT INTO employee_details (`employee_name`, `employee_email`) VALUES(?)";
  const values = [req.body.name, req.body.email];
  dbInfo.query(sql, [values], (err, result) => {
    if (err) return res.json(err);
    return res.json(result);
  });
});

app.get("/read/:id", (req, res) => {
  const sql = "SELECT * FROM employee_details WHERE employee_id=?";
  const id = req.params.id;

  dbInfo.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

app.put("/edit/:id", (req, res) => {
  const sql =
    "UPDATE employee_details SET `employee_name`=? , `employee_email`=? WHERE employee_id=?";
  const id = req.params.id;

  dbInfo.query(
    sql,
    [req.body.employee_name, req.body.employee_email, id],
    (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    }
  );
});

app.delete("/delete/:id", (req, res) => {
  const sql = "DELETE FROM employee_details WHERE employee_id=?";
  const id = req.params.id;

  dbInfo.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

// Sign_Up:
app.post("/Sign_Up", (req, res) => {
  const sql = "INSERT INTO user (`name`, `email`, `password`) VALUES(?) ";

  // Generate a salt and hash the password
  bcrypt.hash(req.body.password.toString(), saltRounds, (err, hash) => {
    if (err) {
      return res.json({ Error: "Error for hashing password" });
    }
    const values = [req.body.name, req.body.email, hash];
    dbInfo.query(sql, [values], (err, result) => {
      if (err) {
        return res.json({ Error: "Inserting data error in server" });
      }
      return res.json({ Status: "Success" }); // yaha kuch nahi likhe matlab else consider karta.
    });
  });
});

// Login:
app.post("/Login", async (req, res) => {
  var login_email_pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  var login_password_pattern = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@]{4,}$/;

  const schema = Joi.object().keys({
    email: Joi.string().regex(login_email_pattern).required(),
    password: Joi.string().regex(login_password_pattern).required(),
  }); //.unknown(true);

  const { error } = schema.validate(req.body, { abortEarly: false });
  if (error) {
    console.log(error);
    return res.json({ error: error.details[0].message });
  } else {
    try {
      const sql = "SELECT * FROM user WHERE email=?";

      dbInfo.query(sql, [req.body.email], (err, data) => {
        if (err) {
          return res.json({ Error: "Login error in server" });
        }

        if (data.length > 0) {
          bcrypt.compare(
            req.body.password.toString(),
            data[0].password,
            (err, response) => {
              if (err) {
                return res.json({ error: "Password compare error" });
              }
              if (response) {
                const name = data[0].name;
                const token = jwt.sign({ name }, "jwt-secret-key", {
                  expiresIn: "1d",
                });
                res.cookie("token", token, { secure: false });
                return res.json({ Status: "Success" });
              } else {
                return res.json({ error: "Password not matched" });
              }
            }
          );
        } else {
          return res.json({ error: "Email not found" });
        }
      });
    } catch (error) {
      console.error(error);
      return res.json({ error: "An error occurred" });
    }
  }
});

// Logout:
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ Status: "Success" });
});

app.listen(8081, () => {
  console.log(`Server is running on ${PORT}`);
});
