import express, {Router} from "express"

import AuthController from "../controllers/AuthController"

//routes
export class AuthRouter {
	public readonly router: Router
	constructor() {
		this.router = express.Router()
		this.router
			.post("/register", AuthController.register)
			.post("/send-otp", AuthController.sendOtp)
			.post("/verify-otp", AuthController.verifyOtp)
			.post("/sign-in", AuthController.signIn)
			.post("/reset-password", AuthController.resetPassword)
	}
}
