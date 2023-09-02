import express, {Router} from "express"

// import AuthController from "../controllers/AuthController"

//routes
export class AuthRouter {
	public readonly router: Router
	constructor() {
		this.router = express.Router()
		this.router
		// .post("/sign-up", AuthController.register)
		// .post("/send-otp", AuthController.sendOtpWithHash)
		// .post("/verify-otp", AuthController.verifyingByHashOtp)
		// .post("/update-user", AuthController.resetPassword)
		// .post("/sign-in", AuthController.signIn)
		// .post("/refresh-token", AuthController.refreshToken)
	}
}
