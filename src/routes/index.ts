import {Router} from "express";
import {healthCheck} from "../controller/health";
import {getUserDetails} from "../controller/user/user.controller";
import {login, logout, resetPassword, verifyOTP} from "../controller/auth/auth.controller";
import {register} from "../controller/auth/auth.controller";
import {authenticate} from "../middleware";


const router = Router();

// get routes
router.get("/health", healthCheck);
router.get('/user', authenticate, getUserDetails);

//post routes
router.post("/login", login);
router.post("/register", register);
router.post("/logout", logout);
router.post("/reset-password", authenticate, resetPassword);
router.post("/verify", verifyOTP);

export default router;
