import {Request, Response, NextFunction} from "express"

export class ApiResponse {
	private res
	constructor(response: Response) {
		this.res = response
	}

	public async successResponse(data: any) {
		data.statusCode = data.statusCode ?? 200
		data.success = true

		return this.res.status(data.statusCode).json(data)
	}

	public async errorResponse(data: any) {
		data.statusCode = data.statusCode ?? 422
		data.success = false

		if (!data.code) {
			switch (data.statusCode) {
				case 400:
					data.code = "unexpected_error"
					break
				case 401:
					data.code = "unauthorized"
					break
				case 403:
					data.code = "not_enough_permissions"
					break
				case 404:
					data.code = "not_found"
					break
				default:
					data.code = "internal_server_error"
					break
			}
		}

		return this.res.status(data.statusCode).json(data)
	}
}
