import {Request, Response, NextFunction} from "express"

import {ServerError} from "../lib/exceptions"

class ApiMiddleware {
	constructor() {}

	public async exceptionHandler(
		err: ServerError,
		req: Request,
		res: Response,
		next: NextFunction
	) {
		const result = {
			message: err.message,
			status: err?.status ?? 400,
			code: err?.code ?? "unexpected_error",
			data: err?.data ?? {}
		}

		return res.status(result.status).json(result)
	}

	// optional middle ware
	public async optionsMiddleware(
		req: Request,
		res: Response,
		next: NextFunction
	) {
		if (req.method !== "OPTIONS") {
			next()
			return
		}

		res.statusCode = 200
		res.end("OK")
	}

	// 404 middleware
	public async middleware404(
		req: Request,
		res: Response,
		next: NextFunction
	) {
		next({
			message: `No router for Requested URL ${req.url}`,
			status: 404,
			code: `not_found`
		})
	}

	// access control middleware
	public async accessControl(
		req: Request,
		res: Response,
		next: NextFunction
	) {
		res.header("Access-Control-Allow-Origin", "*")
		res.header(
			"Access-Control-Allow-Headers",
			"Origin, X-Requested-With, Content-Type, Accept, Authorization"
		)
		res.header("Access-Control-Allow-Credentials", "true")
		res.header("Access-Control-Allow-Methods", "POST,GET,OPTIONS")
		next()
	}
}

export default new ApiMiddleware()
