require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");
const db = require("./config/dbconn");
const jwt = require("jsonwebtoken");
const middleware = require("./middleware/auth");
const { compare, hash } = require("bcrypt");
const e = require("express");
const { rmSync } = require("fs");

const app = express();

const router = express.Router();

const port = parseInt(process.env.PORT);

app.use((req, res, next) => {
    res.set({
        "Access-Control-Allow": "*",
        "Access-Control-Allow": "*",
        "Access-Control-Allow": "*",
    });
    next();
});

app.use(
    express.static("public"),
    router,
    cors(),
    express.json(),
    express.urlencoded({
        extended: true,
    })
);

app.listen(port, () => {
    console.log(`Serving is running on ${port}`);
});

// home
router.get("/", (req, res) => {
    res.sendFile(__dirname + "/" + "index.html");
});

// users
router.get("/users", middleware, (req, res) => {
    if (req.user.role === "Admin") {
        const strQry = `
        SELECT *
        FROM users;
        `;
    db.query(strQry, (err, results) => {
        if (err) throw err;
        res.json({
            status: 200,
            results: results <= 0 ? "Sorry, no product was found" :
            results,
            test: req.user.id
        });
    });
    } else {
        res.json({
            msg: "Only Admins are able to view this"
        });
    }
});

// single user
router.get("/users/:id", (req, res) => {
    const strQry = `
    SELECT *
    FROM users
    WHERE id = ?;
    `;

    db.query(strQry, [req.params.id], (err, results) => {
        if (err) throw err;
        res.json(
            {
                status: 200,
                results: results,
            }
        );
    });
});

// registration
router.post("/users", bodyParser.json(), async (req, res) => {
    try {
        const bd = req.body;
        if (bd.role === "" || bd.role === null) {
            bd.role = "user";
        }
        const emailQ = `
        SELECT email
        FROM users 
        WHERE ?`;
        let email = {
            email: bd.email
        };
        let cart = {
            cart: null
        };
        db.query(emailQ, email, async (err, results) => {
            if (err) throw err;
            if (results.length > 0) {
                res.json({
                    msg: "Email Exists",
                });
            } else {
                bd.password = await hash(bd.password, 10);
                const strQry =`
                ALTER TABLE users 
                AUTO_INCREMENT = 1;
                INSERT INTO users(firstname, lastname, email, password, role)
                VALUES(?, ?, ?, ?, ?);
                 `;
                 db.query(
                    strQry, 
                    [
                        bd.firstname,
                        bd.lastname,
                        bd.email,
                        bd.password,
                        bd.role
                    ],
                    (err) => {
                        if (err) throw err;
                        const payload = {
                            user: {
                                firstname: bd.firstname,
                                lastname: bd.lastname,
                                email: bd.email,
                                role: bd.role,
                                cart: cart.cart,
                            },
                        };
                        jwt.sign(
                            payload,
                            process.env.jwtSecret,
                            {
                                expiresIn: "365d",
                            },
                            (err, token) => {
                                if (err) throw err;
                                res.json({
                                    msg: "Registration Successful",
                                    user: payload.user,
                                    token: token,
                                });
                            }
                        );
                    }
                 );
            }
        });
    } catch (e) {
        console.log(`Registration Error: ${e.message}`);
    }
});

//login
router.patch("/users", bodyParser.json(), (req, res) => {
    try {
        const { email, password } = req.body;
        const strQry =`
        SELECT *
        FROM users
        WHERE email = '${email}';
        `;
        db.query(strQry, async (err, results) => {
            if(err) throw err;
            if (results.length ===0) {
                res.json({
                    msg: "Email not found",
                });
            } else {
                const ismatch = await compare(password, results[0].password);
                if (ismatch === true) {
                    const payload = {
                        user: {
                            id: results[0].id,
                            fistname: results[0].firstname,
                            lastname: results[0].lastname,
                            email: results[0].email,
                            role: results[0].role,
                            cart: results[0].cart
                        },
                    };
                    jwt.sign(
                        payload,
                        process.env.jwtSecret,
                        {
                            expiresIn: "365d",
                        },
                        (err, token) => {
                            if (err) throw err;
                            res.json({
                                msg: "Login Successful",
                                user: payload.user,
                                token: token,
                            });
                        }
                    );
                } else {
                    res.json({
                        msg: "You have entered the wrong password",
                    });
                }
            }
        });
    } catch (e) {
        console.log(`From login: ${e.message}`);
    }
});

// update user
router.put("/users/:id", middleware, bodyParser.json(), async (req, res) => {
    const { firstname, lastname, email, role } = req.body;
    let sql = `
    UPDATE users
    SET ?
    WHERE id = ${req.params.id}`;
    const user = {
        firstname,
        lastname,
        email,
        role
    };
    db.query(sql, user, (err) => {
        if (err) throw err;
        res.json({
            msg: "Update successful",
        });
    });
});

// delete user
router.delete("/users/:id", middleware, (req, res) => {
    if(req.user.user_role === "Admin") {
        const strQry = `
        DELETE 
        FROM users
        WHERE id = ?;
        `;
        db.query(strQry, [req.params.id], (err) => {
            if(err) throw err;
            res.json({
                msg: "User removed",
            });
        });
    } else {
        res.json({
            msg: "Only Admins are allowed to do this",
        });
    }
});

// verify
router.get("/verify", (req, res) => {
    const token = req.header("x-auth-token");
    jwt.verify(token, process.env.jwtSecret, (error, decodedToken) => {
        if(error) {
            res.status(401).json({
                msg: "Unauthorized access",
            });
        } else {
            res.status(200);
            res.send(decodedToken);
        }
    });
});

//====================================================================
//get cart items from user
router.get("/users/:id/cart", middleware, (req, res) => {
    try {
        const strQry = `
        SELECT cart
        FROM users
        WHERE id = ?;
        `;
        db.query(strQry, [req.user.id], (err, results) => {
            if(err) throw err;
            (function Check(a, b) {
                a = parseInt(req.user.id);
                b = parseInt(req.params.id);
                if (a === b) {
                    res.send(results[0].cart);
                } else {
                    res.json({
                        msg: "Please login",
                    });
                }
            })();
        });
    } catch (error) {
        throw error;
    }
});

// add to cart
router.post("/users/:id/cart", middleware, bodyParser.json(), (req, res) => {
    try {
      let { id } = req.body;
      const qCart = `
      SELECT cart
      FROM users
      WHERE id = ?;
      `;
      db.query(qCart, req.user.id, (err, results) => {
        if (err) throw err;
        let cart;
        if (results.length > 0) {
          if (results[0].cart === null) {
            cart = [];
          } else {
            cart = JSON.parse(results[0].cart);
          }
        }
        const strProd = `
        SELECT *
        FROM products
        WHERE id = ${id};
        `;
        db.query(strProd, async (err, results) => {
          if (err) throw err;
          let product = {
            id: results[0].id,
            title: results[0].title,
            image: results[0].image,
            description: results[0].description,
            price: results[0].price,
            userid: results[0].userid
          };
  
          cart.push(product);
          const strQuery = `
          UPDATE users
          SET cart = ?
          WHERE id = ${req.user.id};
          `;
          db.query(strQuery, JSON.stringify(cart), (err) => {
            if (err) throw err;
            res.json({
              results,
              msg: "Product added to Cart"
            });
          });
        });
      });
    } catch (error) {
      console.log(error.message);
    }
  });

//delete singel item from cart
router.delete("/users:id/cart/:id", middleware, (req, res) => {
    const dCart = `
    SELECT cart
    FROM users
    WHERE id = ?;
    `;
    db.query(dCart, req.user.id, (err) => {
        if(err) throw err;
        let item = JSON.parse(results[0].cart).filter((x) => {
            return x.id != req.params.id;
        });
        rmSync.send(item)
        const strQry =`
        UPDATE users
        SET cart = ?
        WHERE id = ?;
        `;
        db.query(
            strQry,
            [JSON.stringify(item), req.user.id],
            (err, data, fields) => {
                if (err) throw err;
                res.json({
                    msg: "item removed from cart",
                });
            }
        );
    });
});

//delete all items from cart
router.delete("/users/:id/cart", middleware, (req, res) => {
    const dCart = `
    SELECT cart
    FROM users
    WHERE id = ?;
    `;
    db.query(dCart, req.user.id, (err, results) => {

    });
    const strQry = `
    UPDATE users
    SET cart = null
    WHERE id = ?;
    `;
    db.query(strQry, [req.user.id], (err, data, fields) => {
        if(err) throw err;
        res.json({
            msg: "item deleted",
        });
    });
});

//====================================================================
//create product
router.post("/products", middleware, bodyParser.json(), (req, res) => {
    try {
        if(req.user.role === "Admin") {
            const bd = req.body;
            const strQry = `
            INSERT INTO products(title, image, description, price, userid)
            VALUES(?, ?, ?, ?, ?);
            `;
            db.query(
                strQry,
                [
                    bd.title,
                    bd.image,
                    bd.description,
                    bd.price,
                    req.user.id
                ],
                (err) => {
                    if(err) throw err;
                    res.json({
                        added: bd,
                        msg: "Product added",
                    });
                }
            );
        } else {
            res.json({
                msg: "Only Admins are allowed to add products",
            });
        }
    } catch {
        console.log(`create new product: ${e.message}`);
    }
})

// get products
router.get("/products", (req, res) => {
    const strQry =`
    SELECT *
    FROM products;
    `;
    db.query(strQry,(err, results) => {
        if(err) throw err;
        res.json({
            status: 200,
            results: results,
        });
    });
});

// get product
router.get("/products/:id", (req, res) => {
    const strQry =`
    SELECT *
    FROM products
    WHERE id = ?;
    `;
    db.query(strQry, [req.params.id], (err, results) => {
        if(err) throw err;
        res.json({
            status: 200,
            results: results.length <= 0 ? "Sorry, no product was found.": results,
        });
    });
});

// update product
router.put("/products/:id", middleware, bodyParser.json(), async (req, res) => {
    const { title, image, description, price } = req.body;
    let sql = `UPDATE products SET ? WHERE id = ${req.params.id}`;
    const product = {
        title,
        image,
        description,
        price
    };
    db.query(sql, product, (err) => {
        if(err) throw err;
        res.json({
            msg: "update successful",
        });
    });
});

//delete product
router.delete("/products/:id", middleware, (req, res) => {
    const strQry =`
    DELETE FROM products
    WHERE id = ?;
    `;
    db.query(strQry, [req.params.id], (err) => {
        if(err) throw err;
        res.json({
            msg: "delete successful",
        });
    });
});