import express from "express"

import {AuthRouter} from "."

const router = express.Router()

// auth routes
router.use("/v1/auth", new AuthRouter().router)

export default router
