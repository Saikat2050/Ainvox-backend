import express from "express"

import {AuthRouter, UserRouter} from "."

const router = express.Router()

// auth routes
router.use("/v1/auth", new AuthRouter().router)
router.use("/v1/user", new UserRouter().router)

export default router
