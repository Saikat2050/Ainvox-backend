import {Request, Response, NextFunction} from "express"

class ApiMiddleware {
	constructor() {}

	public async exceptionHandler(
		err: any,
		req: Request,
		res: Response,
		next: NextFunction
	) {
		const errStatus = err.statusCode || 422
		const errMsg = err.message || "Something went wrong"
		const errCode = err.code || "internal_server_error"

		res.status(errStatus).json({
			success: false,
			statusCode: errStatus,
			message: errMsg,
			code: errCode,
			stack: process.env.NODE_ENV === "development" ? err.stack : {}
		})
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
			message: `No router for Requested URL ${req.originalUrl}`,
			statusCode: 404,
			errCode: `not_found`
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
