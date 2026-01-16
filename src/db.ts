// db.js
import pkg from "pg";
const { Pool } = pkg;

// We use this to connect from loacl pg admin
// const pool = new Pool({
//     host: "localhost",
//     user: "postgres",
//     password: "Elephant0110",
//     database: "auth_service",
//     port: 5432,
// });
console.log('>>>>>X',process.env.DATABASE_URL);
//We use this to connect from supabase
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl : {rejectUnauthorized: false,},
})

// pool.on("connect", () => {
//     console.log('DB Connected');
// })

export default pool;