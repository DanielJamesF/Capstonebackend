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
    if (req.user.user_role === "Admin") {
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
            test: req.user.user_id,
        });
    });
    } else {
        res.json({
            msg: "Only Admins are able to view this"
        });
    }
});

// single user
router.get("/users/:user_id", (req, res) => {
    const strQry = `
    SELECT *
    FROM users
    WHERE user_id = ?;
    `;

    db.query(strQry, [req.params.user_id], (err, results) => {
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
        if (bd.user_role === "" || bd.user_role === null) {
            bd.user_role = "user";
        }
        const emailQ = "SELECT user_email from users WHERE ?";
        let user_email = {
            user_email: bd.user_email,
        };
        let cart = {
            cart: null,
        };

        db.query(emailQ, user_email, async (err, results) => {
            if (err) throw err;
            if (results.length > 0) {
                res.json({
                    msg: "Email Exists",
                });
            } else {
                bd.user_password = await hash(bd.user_password, 10);
                const strQry =`
                
                ALTER TABLE users AUTO_INCREMENT = 1;

                INSERT INTO users(user_name, user_surname, user_email, user_password, user_role)
                VALUES(?, ?, ?, ?, ?);
                 `;
                 db.query(
                    strQry, 
                    [
                        bd.user_name,
                        bd.user_surname,
                        bd.user_email,
                        bd.user_password,
                        bd.user_role
                    ],
                    (err) => {
                        if (err) throw err;
                        const payload = {
                            user: {
                                user_name: bd.user_name,
                                user_surname: bd.user_surname,
                                user_email: bd.user_email,
                                user_role: bd.user_role,
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
        const { user_email, user_password } = req.body;
        const strQry =`
        SELECT *
        FROM users
        WHERE user_email = '${user_email}';
        `;
        db.query(strQry, async (err, results) => {
            if(err) throw err;
            if (results.length ===0) {
                res.json({
                    msg: "Email not found",
                });
            } else {
                const ismatch = await compare(user_password, results[0].user_password);
                if (ismatch === true) {
                    const payload = {
                        user: {
                            user_id: results[0].user_id,
                            user_name: results[0].user_name,
                            user_surname: results[0].user_surname,
                            user_email: results[0].user_email,
                            user_role: results[0].user_role,
                            cart: results[0].cart,
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
router.put("/users/:user_id", middleware, bodyParser.json(), async (req, res) => {
    const { user_name, user_surname, user_email, user_role } = req.body;
    let sql = `UPDATE users SET ? WHERE user_id = ${req.params.user_id}`;
    const user = {
        user_name,
        user_surname,
        user_email,
        user_role,
    };
    db.query(sql, user, (err) => {
        if (err) throw err;
        res.json({
            msg: "Update successful",
        });
    });
});

// delete user
router.delete("/users/:user_id", middleware, (req, res) => {
    if(req.user.user_role === "Admin") {
        const strQry = `
        DELETE FROM users
        WHERE user_id = ?;
        `;
        db.query(strQry, [req.params.user_id], (err) => {
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
router.get("/users/:user_id/cart", middleware, (req, res) => {
    try {
        const strQry = "SELECT cart FROM users WHERE user_id = ?";
        db.query(strQry, [req.user.user_id], (err, results) => {
            if(err) throw err;
            (function Check(a, b) {
                a = parseInt(req.user.user_id);
                b = parseInt(req.params.user_id);
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
router.post("/users/:user_id/cart", middleware, bodyParser.json(), (req, res) => {
    try {
        let {product_id} = req.body;
        const qCart = `
        SELECT cart
        FROM users
        WHERE user_id = ?;
        `;
        db.query(qCart, req.user.user_id, (err, results) => {
            if(err) throw err;
            let cart;
            if(results.length > 0) {
                if(results[0].cart === null) {
                    cart = [];
                } else {
                    cart = JSON.parse(results[0].cart);
                }
            }
            const strProd =`
            SELECT *
            FROM products
            WHERE product_id = ${product_id};
            `;
            db.query(strProd, async (err, results) => {
                if (err) throw err;

                let product = {
                    product_id: results[0].product_id,
                    product_name: results[0].product_name,
                    product_img: results[0].product_img,
                    product_desc: results[0].product_desc,
                    product_category: results[0].product_category,
                    product_price: results[0].product_price,
                    product_stock: results[0].product_stock,
                    product_totalamount: results[0].product_totalamount,
                    user_id: results[0].user_id,
                };
                cart.push(product);
                const strQry = `
                UPDATE users
                SET cart ?
                WHERE (user_id = ${req.user.user_id})`;
                db.query(strQry, JSON.stringify(cart),
                (err) => {
                    if(err) throw err;
                    res.json({
                        results,
                        msg: "Product added to cart",
                    });
                });
            });
        });
    } catch (error) {
        console.log(error)
    }
});

//delete singel item from cart
router.delete("/users:user_id/cart/:product_id", middleware, (req, res) => {
    const dCart = `
    SELECT cart
    FROM users
    WHERE usr_id = ?`;
    db.query(dCart, req.user.user_id, (err) => {
        if(err) throw err;
        let item = JSON.parse(results[0].cart).filter((x) => {
            return x.product_id != req.params.product_id;
        });
        rmSync.send(item)
        const strQry =`
        UPDATE users
        SET cart = ?
        WHERE user_id = ?;
        `;
        db.query(
            strQry,
            [JSON.stringify(item), req.user.user_id],
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
router.delete("/users/:user_id/cart", middleware, (req, res) => {
    const dCart = `
    SELECT cart
    FROM users
    WHERE user_id = ?`;
    db.query(dCart, req.user.user_id, (err, results) => {

    });
    const strQry = `
    UPDATE users
    SET cart = null
    WHERE (user_id = ?)`;
    db.query(strQry, [req.user.user_id], (err, data, fields) => {
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
        if(req.user.user_role === "Admin") {
            const bd = req.body;
            bd.product_totalamount = bd.product_stock * bd.product_price;
            const strQry = `
            INSERT INTO products(product_name, product_img, product_desc, product_price, product_stock, product_totalamount, user_id)
            VALUES(?, ?, ?, ?, ?, ?, ?);
            `;
            db.query(
                strQry,
                [
                    bd.product_name,
                    bd.product_img,
                    bd.product_desc,
                    bd.product_price,
                    bd.product_stock,
                    bd.product_totalamount,
                    req.user.user_id,
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
router.get("/products/:product_id", (req, res) => {
    const strQry =`
    SELECT *
    FROM products
    WHERE product_id = ?;
    `;
    db.query(strQry, [req.params.product_id], (err, results) => {
        if(err) throw err;
        res.json({
            status: 200,
            results: results.length <= 0 ? "Sorry, no product was found.": results,
        });
    });
});

// update product
router.put("/products/:product_id", middleware, bodyParser.json(), async (req, res) => {
    const { product_name, product_img, product_desc, product_price, product_stock } = req.body;
    let sql = `UPDATE products SET ? WHERE product_id = ${req.params.product_id}`;
    const product = {
        product_name,
        product_img,
        product_desc,
        product_price,
        product_stock
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
    WHERE product_id = ?;
    `;
    db.query(strQry, [req.params.id], (err) => {
        if(err) throw err;
        res.json({
            msg: "delete successful",
        });
    });
});