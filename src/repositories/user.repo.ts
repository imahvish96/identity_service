import pool from "../db"

export async function createUser(username: string, email: string) {
    try {
        const result = await pool.query(
            `INSERT INTO auth_service."users" (username, email)
             VALUES ($1, $2) RETURNING "id"`,
            [username, email]
        );

        return result.rows[0];
    } catch (error) {
        console.log(error)
    }
}

export async function findUser(email: string) {
    try {
        const result = await pool.query(
            ` SELECT u.id,
                     u.email,
                     c.password_hash
              FROM auth_service.users u
                       JOIN auth_service.credentials c
                            ON u.id = c.user_id
              WHERE u.email = $1;`,
            [email]
        );
        return result.rows[0];
    } catch (error) {
        console.log(error)
    }

}

export async function saveRefreshToken(userId: string, refreshToken: string) {
    const result = await pool.query(
        `INSERT INTO auth_service."refresh_tokens" ("user_id", token_hash, expires_at)
         VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
        [userId, refreshToken]
    );

    return result.rows[0];
}

export async function getUserByName(username: string) {
    const result = await pool.query(
        `SELECT *
         FROM auth_service."users"
         WHERE username = $1`, [username]
    );
    return result.rows[0];
}

export async function deleteRefreshToken(token: string) {
    await pool.query(
        `DELETE
         FROM auth_service."refresh_tokens"
         WHERE token_hash = $1`, [token]
    );
}
