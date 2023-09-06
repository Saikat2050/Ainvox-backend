import express, {Router} from "express"

import AuthController from "../controllers/AuthController"

//routes
export class AuthRouter {
	public readonly router: Router
	constructor() {
		this.router = express.Router()
		this.router
			.post("/register", AuthController.register)
			// .post("/send-otp", AuthController)
			// .post("/verify-otp", AuthController)
			// .post("/update-user", AuthController)
			.post("/sign-in", AuthController.signIn)
		// .post("/sign-out", AuthController)
		// .post("/reset-password", AuthController)
		// .post("/list-user", AuthController)
		// .post("/delete-user", AuthController)
	}
}
