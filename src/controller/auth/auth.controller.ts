import {Request, Response} from "express";
import os from "os";
import bcrypt from "bcrypt";
import pool from "../../db";
import {
    isValidEmail,
    generateAccessToken,
    generateRefreshToken,
    generateOTP,
    encrypt,
    generateVerifyToken
} from "../../utility";
import {createUser, deleteRefreshToken, findUser, saveRefreshToken} from "../../repositories/user.repo";
import {savePassword, updatePassword} from "../../repositories/credentials.repo";
import {User, VerifyPayload} from "../../types/user.types";
import {loadTemplate} from "../../utility/template";
import {sendMail} from "../../services/mail.service";
import jwt from "jsonwebtoken";

export async function login(req: Request, res: Response) {
    const {email, password} = req.body;
    if (!email || !password) {
        return res.status(400).send({
            code: "AUTH_EMPTY_DETAILS",
            message: "Invalid email or password",
        });
    }
    if (!isValidEmail(email)) {
        return res.status(400).send({
            code: "AUTH_INVALID_EMAIL_FORMAT",
            message: "Please enter valid email",
        });
    }
    if (password.length < 8) {
        return res.status(400).send({
            code: "AUTH_PASSWORD_TOO_SHORT",
            message: "Password must be at least 8 characters long",
        });
    }
    try {
        // await pool.query("BEGIN");
        const usersDetails: User = await findUser(email);
        if (!usersDetails) {
            return res.status(400).send({
                code: "AUTH_USER_NOT_FOUND",
                message: "Invalid Email or Password",
            });
        }

        // await pool.query("COMMIT");
        const isPasswordVerified = await bcrypt.compare(
            password,
            usersDetails.password_hash
        );

        if (isPasswordVerified) {
            const userId = usersDetails.id;
            if (!usersDetails.is_verified) {
                const OTP = generateOTP();
                const hashedOTP = encrypt(OTP);
                await pool.query(
                    `INSERT INTO auth_service.login_otp (user_id, otp_hash, expires_at)
                     VALUES ($1, $2, NOW() + INTERVAL '5 minutes') ON CONFLICT (user_id) DO
                    UPDATE SET
                        otp_hash = EXCLUDED.otp_hash,
                        expires_at = EXCLUDED.expires_at,
                        attempts = 0`,
                    [userId, hashedOTP]
                );
                const verifyToken = generateVerifyToken(userId);
                res.cookie(
                    "verifyToken", verifyToken, {
                        httpOnly: true,
                        secure: true,
                        sameSite: "strict",
                        maxAge: 10 * 60 * 1000, // 10 minutes
                    }
                )
                const rawIpAddress = req.connection.remoteAddress;
                const verifyTemplate = loadTemplate("verify", {
                    timestamp: new Date().toLocaleString("en-IN", {
                        timeZone: "Asia/Kolkata"
                    }),
                    otp: OTP,
                    ip: rawIpAddress!,
                    device: req.headers["user-agent"]!,
                });

                await sendMail({
                    to: "sanufaridi94@gmail.com",
                    subject: "Welcome Please Verify Your Login",
                    html: verifyTemplate,
                }).catch((error) => console.log(error));
                return res.status(200).json({
                    code: "OTP_REQUIRED",
                    message: "OTP sent to your email",
                });
            }
            return loginSuccess(res, userId);
        } else {
            return res.status(401).send({
                code: "AUTH_INVALID_CREDENTIALS",
                message: "Invalid Password",
            });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).send({message: "Something went wrong", error});
    }
}

async function loginSuccess(res: Response, userId: string) {
    const refreshToken = generateRefreshToken(userId);
    const accessToken = generateAccessToken(userId);

    await saveRefreshToken(userId, refreshToken);

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
        accessToken,
        code: "AUTH_SUCCESSFUL",
        message: "You are successfully logged in",
    });
}

export async function register(req: Request, res: Response) {
    const {username, email, password} = req.body;
    if (!username || !email || !password) {
        return res
            .status(400)
            .send({code: "AUTH_REQUIRED_FIELD", error: "Required field, Please enter valid value"});
    }
    const isEmailValid = isValidEmail(email);
    const passwordLen = password.length;
    if (!isEmailValid) {
        return res.status(400).send({code: "AUTH_INVALID_MAIL_FORMAT", error: "Invalid email"});
    }
    if (passwordLen < 8) {
        return res
            .status(400)
            .send({code: "AUTH_PASSWORD_TOO_SHORT", error: "Password at least 8 characters long"});
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query("BEGIN");
        const userResult = await createUser(username, email);
        const userId = userResult.id;
        await savePassword(userId, hashedPassword);
        await pool.query("COMMIT");
        const welcomeTemplate = loadTemplate("Welcome", {name: username});
        try {
            const resendRes = await sendMail({
                to: email,
                subject: "Welcome to Our Service!",
                html: welcomeTemplate,
            })
            if (!resendRes.isSuccess) {
                console.error("Failed to send welcome email", resendRes.data);
            }
        } catch (error) {
            console.error("Failed to send welcome email:", error);
        }
        return res.status(201).json({
            code: "AUTH_USER_REGISTERED_SUCCESSFULLY",
            message: "User registered successfully"
        });
    } catch (error) {
        await pool.query("ROLLBACK");
        console.error(error);
        return res.status(500).json({error: "Internal server error"});
    }
}

export async function logout(req: Request, res: Response) {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
            return res.status(401).send();
        }
        await deleteRefreshToken(refreshToken);
        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
        });
        return res.status(200).send({
            code: "LOGOUT_SUCCESSFUL",
            message: "You have been logged out successfully",
        });

    } catch (error) {
        console.error(error);
        return res.status(500).send({message: "Something went wrong", error});
    }

}

export async function resetPassword(req: Request, res: Response) {
    const {password: currentPassword, new_password, confirm_password} = req.body;
    // @ts-ignore
    let userId = req.user.userId;
    if (!currentPassword) {
        return res.status(400).send({
            code: "RESET_PASSWORD_MISSING_PASSWORD",
            message: "Password is required",
        });
    }

    if (currentPassword.length < 8) {
        return res.status(400).send({
            code: "PASSWORD_TOO_SHORT",
            message: "Password must be at least 8 characters long",
        });
    }
    // confirm if current password is correct
    const hashedPassword = await pool.query(
        `SELECT password_hash
         FROM auth_service.credentials
         WHERE user_id = $1`, [userId]
    );
    const isPasswordVerified = await bcrypt.compare(
        currentPassword,
        hashedPassword.rows[0].password_hash
    );
    if (!isPasswordVerified) {
        return res.status(401).send({
            code: "RESET_PASSWORD_INCORRECT_PASSWORD",
            message: "Incorrect current password",
        });
    }
    if (currentPassword === new_password) {
        return res.status(400).send({
            code: "RESET_PASSWORD_SAME_PASSWORD",
            message: "New password must be different from current password",
        });
    }
    if (new_password.length < 8) {
        return res.status(400).send({
            code: "RESET_PASSWORD_TOO_SHORT",
            message: "New password must be at least 8 characters long",
        });
    }
    if (new_password !== confirm_password) {
        return res.status(400).send({
            code: "RESET_PASSWORD_MISMATCH",
            message: "New password and confirm password do not match",
        });
    }
    try {
        const newHashedPassword = await bcrypt.hash(new_password, 10);
        const isSuccess = await updatePassword(userId!, newHashedPassword);
        if (!isSuccess) {
            return res.status(500).send({
                code: "RESET_PASSWORD_FAILED",
                message: "Failed to reset password, Something Went Wrong",
            });
        }
        await pool.query(`DELETE
                          FROM auth_service.refresh_tokens
                          WHERE user_id = $1`, [userId])
        return res.status(200).send({
            code: "RESET_PASSWORD_SUCCESSFUL",
            message: "Password has been reset successfully",
        });
    } catch (error) {
        console.error(error);
        return res.status(500).send({
            code: "RESET_PASSWORD_INTERNAL_ERROR",
            message: "Internal server error"
        });
    }
}

export async function verifyOTP(req: Request, res: Response) {
    let {otp} = req.body;
    if (!otp || otp.length !== 6) {
        return res.status(400).json({code: "OTP_INVALID", message: "OTP must be 6 digits"});
    }
    let verifyToken = req.cookies.verifyToken;
    if (!verifyToken) {
        return res.status(401).send({
            code: "VERIFY_TOKEN_MISSING",
            message: 'Verification token required',
        });
    }
    let decoded: VerifyPayload;
    try {
        decoded = jwt.verify(verifyToken as string, process.env.VERIFY_TOKEN_SECRET!) as VerifyPayload;
    } catch (error) {
        console.error(error);
        return res.status(500).send({message: "Something went wrong", error});
    }
    console.log("....", decoded.userId)
    try {
        const result = await pool.query(
            `SELECT otp_hash, attempts, expires_at
             FROM auth_service.login_otp
             WHERE user_id = $1
               AND expires_at > NOW()`,
            [decoded.userId]
        );

        if (result.rowCount === 0) {
            return res.status(400).json({code: "OTP_EXPIRED", message: "OTP expired or not found"});
        }
        const row = result.rows[0];
        const hashedInput = encrypt(otp);
        if (row.attempts >= 5) {
            return res.status(429).json({code: "OTP_TOO_MANY_ATTEMPTS", message: "Too many attempts"});
        }
        if (hashedInput !== row.otp_hash) {
            await pool.query(
                `UPDATE auth_service.login_otp
                 SET attempts = attempts + 1
                 WHERE user_id = $1`,
                [decoded.userId]
            );
            return res.status(400).json({code: "OTP_INVALID", message: "Invalid OTP"});
        }
        await pool.query(`DELETE
                          FROM auth_service.login_otp
                          WHERE user_id = $1`, [decoded.userId]);
        await pool.query(`UPDATE auth_service.users
                          SET is_verified = TRUE
                          WHERE id = $1`, [decoded.userId]);
        return loginSuccess(res, decoded.userId as string)
    } catch (error) {
        console.error(error);
        return res.status(500).send({message: "Something went wrong", error});
    }
}
