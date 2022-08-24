const mysql = require('mysql');
require('dotenv').config()
const { createPool } = require ('mysql');

const con = createPool ({
    host: process.env.DBHOST,
    user: process.env.DBUSER,
    password: process.env.DBPASSWORD,
    port: process.env.DBPORT,
    database: process.env.DBNAME,
    multipleStatements: true,
    connectionLimit: 10
});

module.exports = con;