import express, {Router} from "express"

import UserController from "../controllers/UserController"

//routes
export class UserRouter {
	public readonly router: Router
	constructor() {
		this.router = express.Router()
		this.router
			.post("/update-user", UserController.update)
			.post("/list-user", UserController.list)
			.post("/delete-user", UserController.delete)
	}
}
