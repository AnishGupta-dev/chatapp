import express from "express";
import {signup} from "../controllers/auth.controllers.js";
import {login} from "../controllers/auth.controllers.js";
import {logout} from "../controllers/auth.controllers.js";
import { protectRoute } from "../middlewares/auth.middleware.js";
import { updateProfile } from "../controllers/auth.controllers.js";
import { checkAuth } from "../controllers/auth.controllers.js";



const router=express.Router();


router.post("/signup",signup);
router.post("/login",login);
router.post("/logout",logout);
router.put("/update-profile",protectRoute,updateProfile);
router.get("/check",protectRoute,checkAuth)
export default router;