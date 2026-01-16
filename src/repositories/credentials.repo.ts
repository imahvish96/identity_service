import pool from "../db"

export async function savePassword(userId: string, hashedPassword: string) {
    const result = await pool.query(
        `INSERT INTO auth_service."credentials" ("user_id", "password_hash")
         VALUES ($1, $2)`,
        [userId, hashedPassword]
    );

    return result.rows[0];
}

export async function updatePassword(userId: string, hashedPassword: string) {
    const result = await pool.query(
        `UPDATE auth_service."credentials"
         SET password_hash = $2,
             updated_at    = NOW()
         WHERE user_id = $1 RETURNING *`,
        [userId, hashedPassword]
    );

    return result.rows[0];
}

